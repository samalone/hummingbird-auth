import FluentKit
import Foundation

public final class OAuthToken: Model, @unchecked Sendable {
    public static let schema = "oauth_tokens"

    @ID(key: .id)
    public var id: UUID?

    @Field(key: "access_token")
    public var accessToken: String

    @Field(key: "refresh_token")
    public var refreshToken: String

    @Field(key: "client_id")
    public var clientUUID: UUID  // FK to OAuthClient

    @Field(key: "user_id")
    public var userID: UUID

    @Field(key: "scope")
    public var scope: String  // Space-separated

    @Field(key: "access_expires_at")
    public var accessExpiresAt: Date

    @Field(key: "refresh_expires_at")
    public var refreshExpiresAt: Date

    @OptionalField(key: "revoked_at")
    public var revokedAt: Date?

    @Timestamp(key: "created_at", on: .create)
    public var createdAt: Date?

    public init() {}

    public init(
        id: UUID? = nil,
        accessToken: String,
        refreshToken: String,
        clientUUID: UUID,
        userID: UUID,
        scope: String,
        accessExpiresAt: Date,
        refreshExpiresAt: Date
    ) {
        self.id = id
        self.accessToken = accessToken
        self.refreshToken = refreshToken
        self.clientUUID = clientUUID
        self.userID = userID
        self.scope = scope
        self.accessExpiresAt = accessExpiresAt
        self.refreshExpiresAt = refreshExpiresAt
    }

    public var isAccessExpired: Bool { accessExpiresAt < Date() }
    public var isRefreshExpired: Bool { refreshExpiresAt < Date() }
    public var isRevoked: Bool { revokedAt != nil }
    public var scopeSet: Set<String> { Set(scope.split(separator: " ").map(String.init)) }
}
