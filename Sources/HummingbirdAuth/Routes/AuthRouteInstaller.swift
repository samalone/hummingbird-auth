import FluentKit
import Foundation
import Hummingbird
import HummingbirdAuthCore
import Logging
import NIOCore
import WebAuthn

/// Install authentication routes on a router.
///
/// Registers passkey ceremony endpoints under `config.pathPrefix`:
/// - `POST /auth/begin-login`
/// - `POST /auth/finish-login`
/// - `POST /auth/begin-registration` (if invitations enabled)
/// - `POST /auth/finish-registration` (if invitations enabled)
/// - `POST /auth/logout`
///
/// Usage:
/// ```swift
/// installAuthRoutes(on: router, db: db, config: authConfig, logger: logger)
/// ```
public func installAuthRoutes<Context: AuthRequestContextProtocol>(
    on router: Router<Context>,
    db: Database,
    config: AuthConfiguration<Context.User>,
    logger: Logger
) where Context.User: FluentAuthUser {
    let passkeyService = PasskeyService(db: db, logger: logger, config: config.passkey)

    let auth = router.group(RouterPath(config.pathPrefix))

    // MARK: - Login

    auth.post("begin-login") { _, _ -> Response in
        let options = try await passkeyService.beginAuthentication()
        let challengeBase64 = encodeBase64URL(Data(options.challenge))
        let body = BeginLoginResponse(publicKey: options, challengeBase64: challengeBase64)
        return try jsonResponse(body)
    }

    auth.post("finish-login") { request, _ -> Response in
        let bodyBuffer = try await request.body.collect(upTo: 1024 * 1024)
        let body = try JSONDecoder().decode(FinishLoginRequest.self, from: bodyBuffer)

        let challengeBytes = try decodeBase64URL(body.challengeBase64)
        _ = try await passkeyService.verifyChallenge(challengeBytes, type: .authentication)

        guard let credentialData = body.credentialJSON.data(using: .utf8) else {
            throw HTTPError(.badRequest, message: "Invalid credential data")
        }
        let credential = try JSONDecoder().decode(
            AuthenticationCredential.self, from: credentialData
        )

        let credentialIDString = credential.id.asString()
        guard let storedPasskey = try await PasskeyCredential.query(on: db)
            .filter(\.$credentialID == credentialIDString)
            .first()
        else {
            throw HTTPError(.unauthorized, message: "Unknown credential")
        }

        let publicKeyBytes = try decodeBase64URL(storedPasskey.publicKey)
        let verifiedPasskey = try await passkeyService.finishAuthentication(
            expectedChallenge: challengeBytes,
            credential: credential,
            credentialPublicKey: publicKeyBytes,
            credentialCurrentSignCount: UInt32(storedPasskey.signCount)
        )

        // Load the user.
        guard let user = try await Context.User.find(verifiedPasskey.userID, on: db) else {
            throw HTTPError(.unauthorized, message: "User not found")
        }

        // Create session.
        let sessionToken = generateSecureToken()
        let session = AuthSession(
            userID: verifiedPasskey.userID,
            token: sessionToken,
            expiresAt: Date().addingTimeInterval(config.session.sessionTTL)
        )
        try await session.save(on: db)

        // Callback.
        try await config.callbacks.onUserLoggedIn?(user)

        let redirectTo = validateReturnURL(body.returnURL)
            ?? config.callbacks.postLoginRedirect(user)
        let responseBody = FinishLoginResponse(success: true, redirectTo: redirectTo)
        let jsonData = try JSONEncoder().encode(responseBody)

        var response = Response(
            status: .ok,
            headers: [.contentType: "application/json"],
            body: .init(byteBuffer: ByteBuffer(data: jsonData))
        )
        response.setCookie(.authSession(token: sessionToken, config: config.session))

        logger.info("User \(verifiedPasskey.userID) authenticated via passkey")
        return response
    }

    // MARK: - Registration (requires invitations)

    if let invitationConfig = config.invitations {
        let invitationService = InvitationService(
            db: db, logger: logger, config: invitationConfig
        )

        auth.post("begin-registration") { request, _ -> Response in
            let bodyBuffer = try await request.body.collect(upTo: 1024 * 1024)
            let body = try JSONDecoder().decode(
                BeginRegistrationRequest.self, from: bodyBuffer
            )

            _ = try await invitationService.validateToken(body.invitationToken)

            let tempUserID = UUID()
            let options = try await passkeyService.beginRegistration(
                userID: tempUserID,
                username: body.email,
                displayName: body.displayName
            )

            let challengeBase64 = encodeBase64URL(Data(options.challenge))
            let responseBody = BeginRegistrationResponse(
                publicKey: options, challengeBase64: challengeBase64
            )
            return try jsonResponse(responseBody)
        }

        auth.post("finish-registration") { request, _ -> Response in
            let bodyBuffer = try await request.body.collect(upTo: 1024 * 1024)
            let body = try JSONDecoder().decode(
                FinishRegistrationRequest.self, from: bodyBuffer
            )

            let invitation = try await invitationService.validateToken(body.invitationToken)
            let challengeBytes = try decodeBase64URL(body.challengeBase64)
            _ = try await passkeyService.verifyChallenge(challengeBytes, type: .registration)

            guard let credentialData = body.credentialCreationDataJSON.data(using: .utf8) else {
                throw HTTPError(.badRequest, message: "Invalid credential data")
            }
            let registrationCredential = try JSONDecoder().decode(
                RegistrationCredential.self, from: credentialData
            )

            // Create or reclaim user.
            let user: Context.User
            if var existing = try await Context.User.findByEmail(body.email, on: db) {
                let credentialCount = try await PasskeyCredential.query(on: db)
                    .filter(\.$userID == existing.requireID())
                    .count()
                if credentialCount > 0 {
                    throw HTTPError(.conflict, message: "A user with this email already exists")
                }
                existing.displayName = body.displayName
                try await existing.save(on: db)
                user = existing
            } else {
                let newUser = Context.User(displayName: body.displayName, email: body.email)
                try await newUser.save(on: db)
                user = newUser
            }

            let userID = try user.requireID()

            _ = try await passkeyService.finishRegistration(
                userID: userID,
                name: "Passkey",
                challenge: challengeBytes,
                credentialCreationData: registrationCredential
            )

            try await invitationService.consumeInvitation(invitation, consumedByID: userID)
            try await config.callbacks.onUserRegistered?(user)

            // Create session.
            let sessionToken = generateSecureToken()
            let session = AuthSession(
                userID: userID,
                token: sessionToken,
                expiresAt: Date().addingTimeInterval(config.session.sessionTTL)
            )
            try await session.save(on: db)

            let responseBody = FinishRegistrationResponse(success: true, redirectTo: "/")
            let jsonData = try JSONEncoder().encode(responseBody)

            var response = Response(
                status: .ok,
                headers: [.contentType: "application/json"],
                body: .init(byteBuffer: ByteBuffer(data: jsonData))
            )
            response.setCookie(.authSession(token: sessionToken, config: config.session))

            logger.info("New user registered: \(body.email) (\(userID))")
            return response
        }
    }

    // MARK: - Logout

    let authed = router.group(context: AuthenticatedContext<Context>.self)
    authed.post(RouterPath("\(config.pathPrefix)/logout")) { _, context -> Response in
        let userID = context.user.id!
        try await AuthSession.query(on: db)
            .filter(\.$userID == userID)
            .delete()

        var response = Response.redirect(to: config.callbacks.postLogoutRedirect, type: .normal)
        response.setCookie(.expiredAuthSession(config: config.session))

        logger.info("User \(userID) logged out")
        return response
    }
}

// MARK: - Request/Response Types

struct BeginLoginResponse: Codable, ResponseEncodable {
    let publicKey: PublicKeyCredentialRequestOptions
    let challengeBase64: String
}

struct FinishLoginRequest: Codable {
    let challengeBase64: String
    let credentialJSON: String
    let returnURL: String?
}

struct FinishLoginResponse: Codable {
    let success: Bool
    let redirectTo: String
}

struct BeginRegistrationRequest: Codable {
    let displayName: String
    let email: String
    let invitationToken: String
}

struct BeginRegistrationResponse: Codable, ResponseEncodable {
    let publicKey: PublicKeyCredentialCreationOptions
    let challengeBase64: String
}

struct FinishRegistrationRequest: Codable {
    let displayName: String
    let email: String
    let invitationToken: String
    let challengeBase64: String
    let credentialCreationDataJSON: String
}

struct FinishRegistrationResponse: Codable {
    let success: Bool
    let redirectTo: String
}

// MARK: - Helpers

func jsonResponse<T: Encodable & ResponseEncodable>(_ value: T) throws -> Response {
    let data = try JSONEncoder().encode(value)
    return Response(
        status: .ok,
        headers: [.contentType: "application/json"],
        body: .init(byteBuffer: ByteBuffer(data: data))
    )
}

/// Validate a return URL to prevent open redirect vulnerabilities.
func validateReturnURL(_ returnURL: String?) -> String? {
    guard let url = returnURL, !url.isEmpty, url.hasPrefix("/"), !url.hasPrefix("//") else {
        return nil
    }
    return url
}
