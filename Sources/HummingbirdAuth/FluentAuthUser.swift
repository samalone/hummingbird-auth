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

    /// Required empty init for Fluent.
    init()
}

extension FluentAuthUser {
    /// Find a user by email address using a raw field key filter.
    public static func findByEmail(_ email: String, on db: Database) async throws -> Self? {
        try await Self.query(on: db)
            .filter(.path([emailFieldKey], schema: Self.schema), .equal, .bind(email))
            .first()
    }
}
