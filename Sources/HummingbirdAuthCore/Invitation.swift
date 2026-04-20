import FluentKit
import Foundation

public final class Invitation: Model, @unchecked Sendable {
    public static let schema = "auth_invitations"

    @ID(key: .id)
    public var id: UUID?

    @Field(key: "token")
    public var token: String

    @OptionalField(key: "email")
    public var email: String?

    @OptionalField(key: "invited_by_id")
    public var invitedByID: UUID?

    @Field(key: "expires_at")
    public var expiresAt: Date

    @OptionalField(key: "consumed_at")
    public var consumedAt: Date?

    @OptionalField(key: "consumed_by_id")
    public var consumedByID: UUID?

    @Timestamp(key: "created_at", on: .create)
    public var createdAt: Date?

    public init() {}

    public init(
        id: UUID? = nil,
        token: String,
        email: String? = nil,
        invitedByID: UUID? = nil,
        expiresAt: Date
    ) {
        self.id = id
        self.token = token
        self.email = email
        self.invitedByID = invitedByID
        self.expiresAt = expiresAt
    }

    public var isValid: Bool {
        consumedAt == nil && expiresAt > Date()
    }

    public static func cleanupExpired(on database: Database) async throws {
        try await Invitation.query(on: database)
            .filter(\.$expiresAt < Date())
            .filter(\.$consumedAt == nil)
            .delete()
    }
}
