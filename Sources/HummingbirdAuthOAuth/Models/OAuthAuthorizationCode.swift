import FluentKit
import Foundation

public final class OAuthAuthorizationCode: Model, @unchecked Sendable {
    public static let schema = "oauth_authorization_codes"

    @ID(key: .id)
    public var id: UUID?

    @Field(key: "code")
    public var code: String

    @Field(key: "client_id")
    public var clientUUID: UUID  // FK to OAuthClient

    @Field(key: "user_id")
    public var userID: UUID

    @Field(key: "redirect_uri")
    public var redirectURI: String

    @Field(key: "scope")
    public var scope: String  // Space-separated

    @Field(key: "code_challenge")
    public var codeChallenge: String

    @Field(key: "code_challenge_method")
    public var codeChallengeMethod: String

    @Field(key: "expires_at")
    public var expiresAt: Date

    @OptionalField(key: "consumed_at")
    public var consumedAt: Date?

    @Timestamp(key: "created_at", on: .create)
    public var createdAt: Date?

    public init() {}

    public init(
        id: UUID? = nil,
        code: String,
        clientUUID: UUID,
        userID: UUID,
        redirectURI: String,
        scope: String,
        codeChallenge: String,
        codeChallengeMethod: String = "S256",
        expiresAt: Date
    ) {
        self.id = id
        self.code = code
        self.clientUUID = clientUUID
        self.userID = userID
        self.redirectURI = redirectURI
        self.scope = scope
        self.codeChallenge = codeChallenge
        self.codeChallengeMethod = codeChallengeMethod
        self.expiresAt = expiresAt
    }

    public var isExpired: Bool { expiresAt < Date() }
    public var isConsumed: Bool { consumedAt != nil }
}
