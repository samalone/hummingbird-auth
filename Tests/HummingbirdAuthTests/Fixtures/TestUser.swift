import FluentKit
import Foundation

@testable import HummingbirdAuth
@testable import HummingbirdAuthCore

/// Shared Fluent-backed user model for hummingbird-auth tests.
///
/// Conforms to both `AuthUser` (so tests can wire it into
/// `AuthRequestContextProtocol`) and `FluentAuthUser` (so tests that exercise
/// admin routes can query / save it against Fluent). Tests that only need the
/// foreign-key target for `auth_invitations.consumed_by_id` can also use this
/// model — the extra conformances don't get in the way.
final class TestUser: Model, AuthUser, @unchecked Sendable {
    static let schema = "users"

    @ID(key: .id)
    var id: UUID?

    @Field(key: "email")
    var email: String

    @Field(key: "display_name")
    var displayName: String

    @Field(key: "is_admin")
    var isAdmin: Bool

    @Timestamp(key: "created_at", on: .create)
    var createdAt: Date?

    init() {
        self.email = ""
        self.displayName = ""
        self.isAdmin = false
    }

    init(displayName: String, email: String) {
        self.email = email
        self.displayName = displayName
        self.isAdmin = false
    }

    init(email: String, displayName: String, isAdmin: Bool) {
        self.email = email
        self.displayName = displayName
        self.isAdmin = isAdmin
    }

    init(id: UUID, email: String, displayName: String) {
        self.id = id
        self.email = email
        self.displayName = displayName
        self.isAdmin = false
    }
}

extension TestUser: FluentAuthUser {
    static let emailFieldKey: FieldKey = "email"
}

/// Shared migration creating the `users` table used by `TestUser` across the
/// test suite.
struct CreateTestUsers: AsyncMigration {
    func prepare(on database: Database) async throws {
        try await database.schema(TestUser.schema)
            .id()
            .field("email", .string, .required)
            .field("display_name", .string, .required)
            .field("is_admin", .bool, .required, .sql(.default(false)))
            .field("created_at", .datetime)
            .unique(on: "email")
            .create()
    }

    func revert(on database: Database) async throws {
        try await database.schema(TestUser.schema).delete()
    }
}
