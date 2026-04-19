import FluentKit
import Foundation
import HummingbirdAuthCore

/// Bridges `AuthUser` with Fluent's `Model`, adding query capabilities
/// needed by the auth services.
///
/// Apps should conform their User model to this protocol:
/// ```swift
/// extension AppUser: FluentAuthUser {
///     static let emailFieldKey: FieldKey = "email"
/// }
/// ```
public protocol FluentAuthUser: AuthUser, Model where IDValue == UUID {
    /// The Fluent field key for the email column.
    static var emailFieldKey: FieldKey { get }

    /// The Fluent field key for the is-admin column. Defaults to `"is_admin"`.
    static var isAdminFieldKey: FieldKey { get }

    /// Required empty init for Fluent.
    init()
}

extension FluentAuthUser {
    /// Most apps follow the example convention.
    public static var isAdminFieldKey: FieldKey { "is_admin" }

    /// Find a user by email address using a raw field key filter.
    public static func findByEmail(_ email: String, on db: Database) async throws -> Self? {
        try await Self.query(on: db)
            .filter(.path([emailFieldKey], schema: Self.schema), .equal, .bind(email))
            .first()
    }

    /// Count the number of users flagged as admins.
    public static func countAdmins(on db: Database) async throws -> Int {
        try await Self.query(on: db)
            .filter(.path([isAdminFieldKey], schema: Self.schema), .equal, .bind(true))
            .count()
    }
}
