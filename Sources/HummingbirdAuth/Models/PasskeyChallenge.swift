import FluentKit
import Foundation

public enum ChallengeType: String, Codable, Sendable {
    case registration
    case authentication
}

public final class PasskeyChallenge: Model, @unchecked Sendable {
    public static let schema = "passkey_challenges"

    @ID(key: .id)
    public var id: UUID?

    @Field(key: "challenge")
    public var challenge: String

    @Enum(key: "type")
    public var type: ChallengeType

    @Field(key: "expires_at")
    public var expiresAt: Date

    // Registration context — bound at begin-registration so that
    // finish-registration uses server-stored values, not client-supplied ones.
    @OptionalField(key: "registration_email")
    public var registrationEmail: String?

    @OptionalField(key: "registration_display_name")
    public var registrationDisplayName: String?

    @OptionalField(key: "registration_invitation_token")
    public var registrationInvitationToken: String?

    @Timestamp(key: "created_at", on: .create)
    public var createdAt: Date?

    public init() {}

    public init(
        id: UUID? = nil,
        challenge: String,
        type: ChallengeType,
        expiresAt: Date,
        registrationEmail: String? = nil,
        registrationDisplayName: String? = nil,
        registrationInvitationToken: String? = nil
    ) {
        self.id = id
        self.challenge = challenge
        self.type = type
        self.expiresAt = expiresAt
        self.registrationEmail = registrationEmail
        self.registrationDisplayName = registrationDisplayName
        self.registrationInvitationToken = registrationInvitationToken
    }

    public var isExpired: Bool {
        expiresAt < Date()
    }

    public static func cleanupExpired(on database: Database) async throws {
        try await PasskeyChallenge.query(on: database)
            .filter(\.$expiresAt < Date())
            .delete()
    }
}
