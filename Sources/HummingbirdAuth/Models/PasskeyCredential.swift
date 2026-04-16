import FluentKit
import Foundation

public final class PasskeyCredential: Model, @unchecked Sendable {
    public static let schema = "passkey_credentials"

    @ID(key: .id)
    public var id: UUID?

    @Field(key: "user_id")
    public var userID: UUID

    @Field(key: "name")
    public var name: String

    @Field(key: "credential_id")
    public var credentialID: String

    @Field(key: "public_key")
    public var publicKey: String

    @Field(key: "sign_count")
    public var signCount: Int64

    @OptionalField(key: "transports")
    public var transports: String?

    @OptionalField(key: "aaguid")
    public var aaguid: String?

    @Timestamp(key: "created_at", on: .create)
    public var createdAt: Date?

    @Timestamp(key: "updated_at", on: .update)
    public var updatedAt: Date?

    public init() {}

    public init(
        id: UUID? = nil,
        userID: UUID,
        name: String,
        credentialID: String,
        publicKey: String,
        signCount: Int64,
        transports: String? = nil,
        aaguid: String? = nil
    ) {
        self.id = id
        self.userID = userID
        self.name = name
        self.credentialID = credentialID
        self.publicKey = publicKey
        self.signCount = signCount
        self.transports = transports
        self.aaguid = aaguid
    }
}
