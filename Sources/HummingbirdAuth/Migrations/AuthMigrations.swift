import FluentKit
import HummingbirdFluent

/// Add all hummingbird-auth migrations to the Fluent instance.
///
/// Call this after adding your app's User table migration.
/// - Parameters:
///   - fluent: The Fluent instance.
///   - userTable: Schema name of your User model (default: "users").
public func addAuthMigrations(to fluent: Fluent, userTable: String = "users") async {
    await fluent.migrations.add(CreatePasskeyChallenges())
    await fluent.migrations.add(CreatePasskeyCredentials(userTable: userTable))
    await fluent.migrations.add(CreateAuthSessions(userTable: userTable))
    await fluent.migrations.add(CreateInvitations(userTable: userTable))
}

public struct CreatePasskeyChallenges: AsyncMigration {
    public init() {}

    public func prepare(on database: Database) async throws {
        try await database.schema(PasskeyChallenge.schema)
            .id()
            .field("challenge", .string, .required)
            .field("type", .string, .required)
            .field("expires_at", .datetime, .required)
            .field("registration_email", .string)
            .field("registration_display_name", .string)
            .field("registration_invitation_token", .string)
            .field("created_at", .datetime)
            .unique(on: "challenge")
            .create()
    }

    public func revert(on database: Database) async throws {
        try await database.schema(PasskeyChallenge.schema).delete()
    }
}

public struct CreatePasskeyCredentials: AsyncMigration {
    let userTable: String

    public init(userTable: String = "users") {
        self.userTable = userTable
    }

    public func prepare(on database: Database) async throws {
        try await database.schema(PasskeyCredential.schema)
            .id()
            .field("user_id", .uuid, .required,
                   .references(userTable, "id", onDelete: .cascade))
            .field("name", .string, .required)
            .field("credential_id", .string, .required)
            .field("public_key", .string, .required)
            .field("sign_count", .int64, .required)
            .field("transports", .string)
            .field("aaguid", .string)
            .field("created_at", .datetime)
            .field("updated_at", .datetime)
            .unique(on: "credential_id")
            .create()
    }

    public func revert(on database: Database) async throws {
        try await database.schema(PasskeyCredential.schema).delete()
    }
}

public struct CreateAuthSessions: AsyncMigration {
    let userTable: String

    public init(userTable: String = "users") {
        self.userTable = userTable
    }

    public func prepare(on database: Database) async throws {
        try await database.schema(AuthSession.schema)
            .id()
            .field("user_id", .uuid, .required,
                   .references(userTable, "id", onDelete: .cascade))
            .field("token", .string, .required)
            .field("expires_at", .datetime, .required)
            .field("flash_messages_json", .string)
            .field("masquerade_user_id", .uuid)
            .field("real_user_id", .uuid)
            .field("csrf_token", .string, .required)
            .field("created_at", .datetime)
            .unique(on: "token")
            .create()
    }

    public func revert(on database: Database) async throws {
        try await database.schema(AuthSession.schema).delete()
    }
}

public struct CreateInvitations: AsyncMigration {
    let userTable: String

    public init(userTable: String = "users") {
        self.userTable = userTable
    }

    public func prepare(on database: Database) async throws {
        try await database.schema(Invitation.schema)
            .id()
            .field("token", .string, .required)
            .field("email", .string)
            .field("invited_by_id", .uuid,
                   .references(userTable, "id", onDelete: .cascade))
            .field("expires_at", .datetime, .required)
            .field("consumed_at", .datetime)
            .field("consumed_by_id", .uuid,
                   .references(userTable, "id", onDelete: .setNull))
            .field("created_at", .datetime)
            .unique(on: "token")
            .create()
    }

    public func revert(on database: Database) async throws {
        try await database.schema(Invitation.schema).delete()
    }
}
