import FluentKit
import Foundation

public final class OAuthClient: Model, @unchecked Sendable {
    public static let schema = "oauth_clients"

    @ID(key: .id)
    public var id: UUID?

    @Field(key: "client_id")
    public var clientID: String

    @OptionalField(key: "client_secret_hash")
    public var clientSecretHash: String?

    @Field(key: "client_name")
    public var clientName: String

    @Field(key: "redirect_uris")
    public var redirectURIs: String  // JSON array

    @Field(key: "grant_types")
    public var grantTypes: String  // JSON array

    @Field(key: "scope")
    public var scope: String  // Space-separated

    @OptionalField(key: "last_accessed_at")
    public var lastAccessedAt: Date?

    @OptionalField(key: "display_name")
    public var displayName: String?

    @Timestamp(key: "created_at", on: .create)
    public var createdAt: Date?

    public init() {}

    public init(
        id: UUID? = nil,
        clientID: String,
        clientSecretHash: String? = nil,
        clientName: String,
        redirectURIs: String,
        grantTypes: String = "[\"authorization_code\"]",
        scope: String = "read"
    ) {
        self.id = id
        self.clientID = clientID
        self.clientSecretHash = clientSecretHash
        self.clientName = clientName
        self.redirectURIs = redirectURIs
        self.grantTypes = grantTypes
        self.scope = scope
    }

    public var redirectURIList: [String] {
        (try? JSONDecoder().decode([String].self, from: Data(redirectURIs.utf8))) ?? []
    }

    public var grantTypeList: [String] {
        (try? JSONDecoder().decode([String].self, from: Data(grantTypes.utf8))) ?? []
    }

    public var scopeSet: Set<String> {
        Set(scope.split(separator: " ").map(String.init))
    }
}
