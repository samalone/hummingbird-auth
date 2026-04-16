import Foundation

/// Protocol that app-provided User models must conform to.
///
/// The library stores user references as UUID foreign keys and loads users
/// through this protocol's requirements. Apps provide their own Fluent model.
///
/// Example:
/// ```swift
/// final class AppUser: Model, AuthUser, @unchecked Sendable {
///     static let schema = "users"
///     @ID(key: .id) var id: UUID?
///     @Field(key: "display_name") var displayName: String
///     @Field(key: "email") var email: String
///     @Field(key: "is_admin") var isAdmin: Bool
///     @Timestamp(key: "created_at", on: .create) var createdAt: Date?
///     init() {}
///     required init(displayName: String, email: String) { ... }
/// }
/// ```
public protocol AuthUser: Sendable {
    associatedtype IDValue = UUID

    var id: UUID? { get }
    var displayName: String { get set }
    var email: String { get set }

    /// Whether this user has admin privileges. Settable for admin role management.
    var isAdmin: Bool { get set }

    /// Creation timestamp. Used by admin user list for sorting.
    var createdAt: Date? { get }

    /// Create a new user during registration.
    init(displayName: String, email: String)
}

extension AuthUser {
    public var isAdmin: Bool {
        get { false }
        set { }  // No-op for apps that don't support admin roles
    }

    public var createdAt: Date? { nil }
}
