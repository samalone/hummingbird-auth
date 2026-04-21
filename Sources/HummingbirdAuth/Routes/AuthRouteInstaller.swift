import FluentKit
import Foundation
import Hummingbird
import HummingbirdAuthCore
import Logging
import NIOCore
import WebAuthn

/// Install authentication routes on a router or router group.
///
/// Registers passkey ceremony endpoints under `config.pathPrefix`:
/// - `POST {pathPrefix}/begin-login`
/// - `POST {pathPrefix}/finish-login`
/// - `POST {pathPrefix}/begin-registration` (if invitations enabled)
/// - `POST {pathPrefix}/finish-registration` (if invitations enabled)
/// - `POST {pathPrefix}/logout`
///
/// `config.pathPrefix` defaults to `/auth`. The routes land under whatever
/// router or group is passed in, so apps mounted on a sub-path can use
/// `router.group(RouterPath("/myapp"))` as the first argument and the
/// library routes will land under `/myapp/auth/…` automatically.
///
/// Usage:
/// ```swift
/// installAuthRoutes(on: router, db: db, config: authConfig, logger: logger)
/// ```
public func installAuthRoutes<Context: CSRFProtectedContext>(
    on router: some RouterMethods<Context>,
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
        let body = try JSONDecoder().decode(FinishLoginRequest.self, from: Data(bodyBuffer.readableBytesView))

        let challengeBytes = try decodeBase64URL(body.challengeBase64)
        let _ = try await passkeyService.verifyChallenge(challengeBytes, type: .authentication)

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
            body: .init(byteBuffer: ByteBuffer(bytes: jsonData))
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
                BeginRegistrationRequest.self, from: Data(bodyBuffer.readableBytesView)
            )

            let invitation = try await invitationService.validateToken(body.invitationToken)

            // Enforce invitation email constraint: if the invitation was
            // created for a specific email, only that email may register.
            if let invEmail = invitation.email {
                guard invEmail.lowercased() == body.email.lowercased() else {
                    throw HTTPError(.forbidden, message: "This invitation is for a different email address")
                }
            }

            let tempUserID = UUID()
            let options = try await passkeyService.beginRegistration(
                userID: tempUserID,
                username: body.email,
                displayName: body.displayName,
                invitationToken: body.invitationToken
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
                FinishRegistrationRequest.self, from: Data(bodyBuffer.readableBytesView)
            )

            let challengeBytes = try decodeBase64URL(body.challengeBase64)
            let challenge = try await passkeyService.verifyChallenge(challengeBytes, type: .registration)

            // Use the email, displayName, and invitation token that were
            // bound to the challenge at begin-registration, not the values
            // from the client. This prevents an attacker from swapping the
            // email between begin and finish to take over another account.
            guard let registrationEmail = challenge.registrationEmail,
                  let registrationDisplayName = challenge.registrationDisplayName,
                  let registrationInvitationToken = challenge.registrationInvitationToken else {
                throw HTTPError(.badRequest, message: "Challenge is not bound to a registration")
            }

            let invitation = try await invitationService.validateToken(registrationInvitationToken)

            guard let credentialData = body.credentialCreationDataJSON.data(using: .utf8) else {
                throw HTTPError(.badRequest, message: "Invalid credential data")
            }
            let registrationCredential = try JSONDecoder().decode(
                RegistrationCredential.self, from: credentialData
            )

            // Create or reclaim user.
            let user: Context.User
            if var existing = try await Context.User.findByEmail(registrationEmail, on: db) {
                let credentialCount = try await PasskeyCredential.query(on: db)
                    .filter(\.$userID == existing.requireID())
                    .count()
                if credentialCount > 0 {
                    throw HTTPError(.conflict, message: "A user with this email already exists")
                }
                existing.displayName = registrationDisplayName
                try await existing.save(on: db)
                user = existing
            } else {
                var newUser = Context.User(displayName: registrationDisplayName, email: registrationEmail)
                // Auto-promote the first registered user to admin.
                let userCount = try await Context.User.query(on: db).count()
                if userCount == 0 {
                    newUser.isAdmin = true
                }
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

            let consumedInvitation = try await invitationService.consumeInvitation(
                invitation, consumedByID: userID
            )
            try await config.callbacks.onUserRegistered?(user, consumedInvitation)

            // Create session.
            let sessionToken = generateSecureToken()
            let session = AuthSession(
                userID: userID,
                token: sessionToken,
                expiresAt: Date().addingTimeInterval(config.session.sessionTTL)
            )
            try await session.save(on: db)

            // Freshly-registered user is now logged in — send them
            // wherever post-login traffic normally lands.
            let redirectTo = config.callbacks.postLoginRedirect(user)
            let responseBody = FinishRegistrationResponse(success: true, redirectTo: redirectTo)
            let jsonData = try JSONEncoder().encode(responseBody)

            var response = Response(
                status: .ok,
                headers: [.contentType: "application/json"],
                body: .init(byteBuffer: ByteBuffer(bytes: jsonData))
            )
            response.setCookie(.authSession(token: sessionToken, config: config.session))

            logger.info("New user registered: \(registrationEmail) (\(userID))")
            return response
        }
    }

    // MARK: - Logout

    let authed = router.group(context: AuthenticatedContext<Context>.self)
    authed.post(RouterPath("\(config.pathPrefix)/logout")) { request, context -> Response in
        let userID = context.user.id!

        // Delete only the current session (not all sessions for this user).
        if let token = request.cookies[SessionConfiguration.cookieName]?.value {
            try await AuthSession.query(on: db)
                .filter(\.$token == token)
                .delete()
        }

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
        body: .init(byteBuffer: ByteBuffer(bytes: data))
    )
}

/// Validate a return URL to prevent open redirect vulnerabilities.
func validateReturnURL(_ returnURL: String?) -> String? {
    guard let url = returnURL, !url.isEmpty, url.hasPrefix("/"), !url.hasPrefix("//"),
          !url.contains("\\") else {
        return nil
    }
    return url
}
