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

    @Timestamp(key: "created_at", on: .create)
    public var createdAt: Date?

    public init() {}

    public init(id: UUID? = nil, challenge: String, type: ChallengeType, expiresAt: Date) {
        self.id = id
        self.challenge = challenge
        self.type = type
        self.expiresAt = expiresAt
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
