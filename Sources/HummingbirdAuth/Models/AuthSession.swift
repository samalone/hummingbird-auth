import FluentKit
import Foundation
import HummingbirdAuthCore

public final class AuthSession: Model, @unchecked Sendable {
    public static let schema = "auth_sessions"

    @ID(key: .id)
    public var id: UUID?

    @Field(key: "user_id")
    public var userID: UUID

    @Field(key: "token")
    public var token: String

    @Field(key: "expires_at")
    public var expiresAt: Date

    @OptionalField(key: "flash_messages_json")
    public var flashMessagesJSON: String?

    @OptionalField(key: "masquerade_user_id")
    public var masqueradeUserID: UUID?

    @OptionalField(key: "real_user_id")
    public var realUserID: UUID?

    @Field(key: "csrf_token")
    public var csrfToken: String

    @Timestamp(key: "created_at", on: .create)
    public var createdAt: Date?

    public init() {}

    public init(userID: UUID, token: String, expiresAt: Date) {
        self.userID = userID
        self.token = token
        self.expiresAt = expiresAt
        self.csrfToken = generateSecureToken()
    }

    public var isExpired: Bool {
        expiresAt < Date()
    }

    // MARK: - Flash Messages

    public func addFlash(_ level: FlashMessage.Level, _ text: String) {
        var messages = consumeFlashMessagesInternal()
        messages.append(FlashMessage(level, text))
        flashMessagesJSON = try? String(data: JSONEncoder().encode(messages), encoding: .utf8)
    }

    public func consumeFlashMessages() -> [FlashMessage] {
        let messages = consumeFlashMessagesInternal()
        flashMessagesJSON = nil
        return messages
    }

    private func consumeFlashMessagesInternal() -> [FlashMessage] {
        guard let json = flashMessagesJSON, let data = json.data(using: .utf8) else {
            return []
        }
        return (try? JSONDecoder().decode([FlashMessage].self, from: data)) ?? []
    }

    // MARK: - Cleanup

    public static func cleanupExpired(on database: Database) async throws {
        try await AuthSession.query(on: database)
            .filter(\.$expiresAt < Date())
            .delete()
    }
}
