import FluentKit
import HummingbirdFluent

/// Add all OAuth migrations to the Fluent instance.
public func addOAuthMigrations(to fluent: Fluent, userTable: String = "users") async {
    await fluent.migrations.add(CreateOAuthClients())
    await fluent.migrations.add(CreateOAuthAuthorizationCodes(userTable: userTable))
    await fluent.migrations.add(CreateOAuthTokens(userTable: userTable))
}

public struct CreateOAuthClients: AsyncMigration {
    public init() {}

    public func prepare(on database: Database) async throws {
        try await database.schema(OAuthClient.schema)
            .id()
            .field("client_id", .string, .required)
            .field("client_secret_hash", .string)
            .field("client_name", .string, .required)
            .field("redirect_uris", .string, .required)
            .field("grant_types", .string, .required)
            .field("scope", .string, .required)
            .field("last_accessed_at", .datetime)
            .field("display_name", .string)
            .field("created_at", .datetime)
            .unique(on: "client_id")
            .create()
    }

    public func revert(on database: Database) async throws {
        try await database.schema(OAuthClient.schema).delete()
    }
}

public struct CreateOAuthAuthorizationCodes: AsyncMigration {
    let userTable: String

    public init(userTable: String = "users") {
        self.userTable = userTable
    }

    public func prepare(on database: Database) async throws {
        try await database.schema(OAuthAuthorizationCode.schema)
            .id()
            .field("code", .string, .required)
            .field("client_id", .uuid, .required,
                   .references(OAuthClient.schema, "id", onDelete: .cascade))
            .field("user_id", .uuid, .required,
                   .references(userTable, "id", onDelete: .cascade))
            .field("redirect_uri", .string, .required)
            .field("scope", .string, .required)
            .field("code_challenge", .string, .required)
            .field("code_challenge_method", .string, .required)
            .field("expires_at", .datetime, .required)
            .field("consumed_at", .datetime)
            .field("created_at", .datetime)
            .unique(on: "code")
            .create()
    }

    public func revert(on database: Database) async throws {
        try await database.schema(OAuthAuthorizationCode.schema).delete()
    }
}

public struct CreateOAuthTokens: AsyncMigration {
    let userTable: String

    public init(userTable: String = "users") {
        self.userTable = userTable
    }

    public func prepare(on database: Database) async throws {
        try await database.schema(OAuthToken.schema)
            .id()
            .field("access_token", .string, .required)
            .field("refresh_token", .string, .required)
            .field("client_id", .uuid, .required,
                   .references(OAuthClient.schema, "id", onDelete: .cascade))
            .field("user_id", .uuid, .required,
                   .references(userTable, "id", onDelete: .cascade))
            .field("scope", .string, .required)
            .field("access_expires_at", .datetime, .required)
            .field("refresh_expires_at", .datetime, .required)
            .field("revoked_at", .datetime)
            .field("created_at", .datetime)
            .unique(on: "access_token")
            .unique(on: "refresh_token")
            .create()
    }

    public func revert(on database: Database) async throws {
        try await database.schema(OAuthToken.schema).delete()
    }
}
