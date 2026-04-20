import Foundation

/// A plain Swift snapshot of an invitation that was just consumed during
/// registration.
///
/// This DTO lets `AuthCallbacks.onUserRegistered` carry the consumed
/// invitation's metadata without pulling the Fluent `Invitation` model —
/// and therefore the whole FluentKit dependency — into
/// `HummingbirdAuthCore`. Core stays runtime-framework-free; the route
/// installer in `HummingbirdAuth` is responsible for building this DTO
/// from the Fluent model before invoking the callback.
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
