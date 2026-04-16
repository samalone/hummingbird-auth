import FluentKit
import Foundation
import HummingbirdAuthCore
import Logging

public enum InvitationError: Error, Sendable {
    case notFound
    case expired
    case alreadyConsumed
}

/// Manages single-use invitation tokens for registration.
public struct InvitationService: Sendable {
    private let db: Database
    private let logger: Logger
    private let defaultTTL: TimeInterval

    public init(db: Database, logger: Logger, config: InvitationConfiguration = .init()) {
        self.db = db
        self.logger = logger
        self.defaultTTL = config.tokenTTL
    }

    /// Create a new invitation token.
    public func createInvitation(
        email: String? = nil,
        invitedByID: UUID,
        expiresIn: TimeInterval? = nil
    ) async throws -> Invitation {
        let token = generateToken()
        let invitation = Invitation(
            token: token,
            email: email,
            invitedByID: invitedByID,
            expiresAt: Date().addingTimeInterval(expiresIn ?? defaultTTL)
        )
        try await invitation.save(on: db)
        logger.info("Invitation created: \(token.prefix(8))... for \(email ?? "anyone")")
        return invitation
    }

    /// Validate an invitation token. Throws if invalid, expired, or consumed.
    public func validateToken(_ token: String) async throws -> Invitation {
        guard let invitation = try await Invitation.query(on: db)
            .filter(\.$token == token)
            .first()
        else {
            throw InvitationError.notFound
        }

        guard invitation.consumedAt == nil else {
            throw InvitationError.alreadyConsumed
        }

        guard invitation.expiresAt > Date() else {
            throw InvitationError.expired
        }

        return invitation
    }

    /// Mark an invitation as consumed by a user.
    public func consumeInvitation(_ invitation: Invitation, consumedByID: UUID) async throws {
        invitation.consumedAt = Date()
        invitation.consumedByID = consumedByID
        try await invitation.save(on: db)
        logger.info("Invitation consumed: \(invitation.token.prefix(8))... by \(consumedByID)")
    }

    /// Generate a cryptographically random 64-character hex token.
    private func generateToken() -> String {
        var bytes = [UInt8](repeating: 0, count: 32)
        _ = bytes.withUnsafeMutableBufferPointer { buffer in
            SecRandomCopyBytes(kSecRandomDefault, buffer.count, buffer.baseAddress!)
        }
        return bytes.map { String(format: "%02x", $0) }.joined()
    }
}
