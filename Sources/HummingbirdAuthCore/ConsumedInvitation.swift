import Foundation

/// A plain-Swift snapshot of an invitation that was just consumed during
/// registration. Passed to `AuthCallbacks.onUserRegistered` so apps can read
/// the consumed invitation's metadata.
public struct ConsumedInvitation: Sendable {
    public let id: UUID
    public let token: String
    public let email: String?
    public let invitedByID: UUID?
    public let expiresAt: Date
    public let consumedAt: Date
    public let consumedByID: UUID

    public init(
        id: UUID,
        token: String,
        email: String?,
        invitedByID: UUID?,
        expiresAt: Date,
        consumedAt: Date,
        consumedByID: UUID
    ) {
        self.id = id
        self.token = token
        self.email = email
        self.invitedByID = invitedByID
        self.expiresAt = expiresAt
        self.consumedAt = consumedAt
        self.consumedByID = consumedByID
    }
}
