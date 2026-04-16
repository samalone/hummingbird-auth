import FluentKit
import Foundation
import HummingbirdAuthCore
import Logging
import WebAuthn

public enum PasskeyError: Error, Sendable {
    case credentialNotFound
    case challengeNotFound
    case challengeExpired
    case invalidChallenge
}

/// Manages WebAuthn passkey registration and authentication ceremonies.
public struct PasskeyService: Sendable {
    private let webAuthn: WebAuthnManager
    private let db: Database
    private let logger: Logger
    private let challengeTTL: TimeInterval

    public init(
        db: Database,
        logger: Logger,
        config: PasskeyConfiguration
    ) {
        self.webAuthn = WebAuthnManager(
            configuration: WebAuthnManager.Configuration(
                relyingPartyID: config.relyingPartyID,
                relyingPartyName: config.relyingPartyName,
                relyingPartyOrigin: config.relyingPartyOrigin
            )
        )
        self.db = db
        self.logger = logger
        self.challengeTTL = config.challengeTTL
    }

    // MARK: - Registration

    public func beginRegistration(
        userID: UUID,
        username: String,
        displayName: String
    ) async throws -> PublicKeyCredentialCreationOptions {

        let options = webAuthn.beginRegistration(
            user: PublicKeyCredentialUserEntity(
                id: Array(userID.uuidString.utf8),
                name: username,
                displayName: displayName
            ),
            publicKeyCredentialParameters: [
                .init(type: .publicKey, alg: .algES256),
            ]
        )

        // Store the challenge for verification.
        let challengeBase64 = encodeBase64URL(Data(options.challenge))
        let challenge = PasskeyChallenge(
            challenge: challengeBase64,
            type: .registration,
            expiresAt: Date().addingTimeInterval(challengeTTL)
        )
        try await challenge.save(on: db)

        return options
    }

    public func finishRegistration(
        userID: UUID,
        name: String,
        challenge: [UInt8],
        credentialCreationData: RegistrationCredential
    ) async throws -> PasskeyCredential {
        let credential = try await webAuthn.finishRegistration(
            challenge: challenge,
            credentialCreationData: credentialCreationData,
            confirmCredentialIDNotRegisteredYet: { credentialID in
                let count = try await PasskeyCredential.query(on: db)
                    .filter(\.$credentialID == credentialID)
                    .count()
                return count == 0
            }
        )

        let stored = PasskeyCredential(
            userID: userID,
            name: name,
            credentialID: normalizeToBase64URL(credential.id),
            publicKey: encodeBase64URL(Data(credential.publicKey)),
            signCount: Int64(credential.signCount),
            transports: nil,
            aaguid: credential.aaguid.map { String(describing: $0) }
        )
        try await stored.save(on: db)
        return stored
    }

    // MARK: - Authentication

    public func beginAuthentication() async throws -> PublicKeyCredentialRequestOptions {
        try? await PasskeyChallenge.cleanupExpired(on: db)

        let options = webAuthn.beginAuthentication()

        let challengeBase64 = encodeBase64URL(Data(options.challenge))
        let challenge = PasskeyChallenge(
            challenge: challengeBase64,
            type: .authentication,
            expiresAt: Date().addingTimeInterval(challengeTTL)
        )
        try await challenge.save(on: db)

        return options
    }

    public func finishAuthentication(
        expectedChallenge: [UInt8],
        credential: AuthenticationCredential,
        credentialPublicKey: [UInt8],
        credentialCurrentSignCount: UInt32
    ) async throws -> PasskeyCredential {
        let verified = try webAuthn.finishAuthentication(
            credential: credential,
            expectedChallenge: expectedChallenge,
            credentialPublicKey: credentialPublicKey,
            credentialCurrentSignCount: credentialCurrentSignCount
        )

        // Update sign count.
        guard let stored = try await PasskeyCredential.query(on: db)
            .filter(\.$credentialID == verified.credentialID.asString())
            .first()
        else {
            throw PasskeyError.credentialNotFound
        }

        stored.signCount = Int64(verified.newSignCount)
        try await stored.save(on: db)
        return stored
    }

    // MARK: - Challenge Verification

    /// Verify a challenge is valid and not expired, then delete it.
    public func verifyChallenge(_ challengeBytes: [UInt8], type: ChallengeType) async throws -> String {
        let challengeBase64 = encodeBase64URL(Data(challengeBytes))

        guard let stored = try await PasskeyChallenge.query(on: db)
            .filter(\.$challenge == challengeBase64)
            .filter(\.$type == type)
            .first()
        else {
            throw PasskeyError.challengeNotFound
        }

        guard !stored.isExpired else {
            try await stored.delete(on: db)
            throw PasskeyError.challengeExpired
        }

        try await stored.delete(on: db)
        return challengeBase64
    }

    // MARK: - Credential Management

    public func getPasskeys(userID: UUID) async throws -> [PasskeyCredential] {
        try await PasskeyCredential.query(on: db)
            .filter(\.$userID == userID)
            .sort(\.$createdAt, .ascending)
            .all()
    }
}
// Base64URL utilities and generateSecureToken are in HummingbirdAuthCore/Utilities.swift
