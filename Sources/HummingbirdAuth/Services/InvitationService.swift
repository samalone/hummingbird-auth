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
        invitedByID: UUID? = nil,
        expiresIn: TimeInterval? = nil
    ) async throws -> Invitation {
        let token = generateSecureToken()
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

    /// Atomically consume an invitation. Filters on `consumed_at IS NULL` to
    /// prevent TOCTOU races where two concurrent registrations both consume
    /// the same invitation.
    public func consumeInvitation(_ invitation: Invitation, consumedByID: UUID) async throws {
        // Re-fetch with consumed_at == nil filter to narrow the race window.
        guard let fresh = try await Invitation.query(on: db)
            .filter(\.$id == invitation.requireID())
            .filter(\.$consumedAt == nil)
            .first()
        else {
            throw InvitationError.alreadyConsumed
        }
        fresh.consumedAt = Date()
        fresh.consumedByID = consumedByID
        try await fresh.save(on: db)
        logger.info("Invitation consumed: \(fresh.token.prefix(8))... by \(consumedByID)")
    }

}
