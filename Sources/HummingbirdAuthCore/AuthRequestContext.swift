import Foundation
import Hummingbird

/// Minimum context protocol for routes that may have an authenticated user.
///
/// Apps provide a concrete struct conforming to this protocol:
/// ```swift
/// struct AppContext: AuthRequestContextProtocol {
///     typealias User = AppUser
///     var coreContext: CoreRequestContextStorage
///     var user: AppUser?
///     var flashMessages: [FlashMessage]
///     var masqueradingAs: String?
///     var realUserID: UUID?
///     init(source: ApplicationRequestContextSource) { ... }
/// }
/// ```
public protocol AuthRequestContextProtocol: RequestContext {
    associatedtype User: AuthUser

    /// The authenticated user, if any. Set by SessionMiddleware.
    /// During masquerade, this is the *target* user, not the admin.
    var user: User? { get set }

    /// Flash messages consumed from the session.
    var flashMessages: [FlashMessage] { get set }

    /// When masquerading, the display name of the target user.
    /// Non-nil indicates an active masquerade session.
    var masqueradingAs: String? { get set }

    /// The real admin user's ID during masquerade. Nil when not masquerading.
    var realUserID: UUID? { get set }
}

/// Child context for routes requiring an authenticated user.
public struct AuthenticatedContext<Parent: AuthRequestContextProtocol>: ChildRequestContext, Sendable {
    public typealias ParentContext = Parent

    public var coreContext: CoreRequestContextStorage
    public let user: Parent.User
    public let flashMessages: [FlashMessage]
    public let masqueradingAs: String?
    public let realUserID: UUID?

    public init(context: Parent) throws {
        guard let user = context.user else {
            throw HTTPError(.unauthorized)
        }
        self.coreContext = context.coreContext
        self.user = user
        self.flashMessages = context.flashMessages
        self.masqueradingAs = context.masqueradingAs
        self.realUserID = context.realUserID
    }
}

/// Child context for routes requiring admin access.
///
/// Throws 401 if not authenticated, 403 if not an admin.
/// During masquerade, the real admin retains admin access even though
/// context.user is the target (non-admin) user.
public struct AdminContext<Parent: AuthRequestContextProtocol>: ChildRequestContext, Sendable {
    public typealias ParentContext = Parent

    public var coreContext: CoreRequestContextStorage
    public let user: Parent.User
    public let flashMessages: [FlashMessage]
    public let masqueradingAs: String?
    public let realUserID: UUID?

    public init(context: Parent) throws {
        guard let user = context.user else {
            throw HTTPError(.unauthorized)
        }
        // Allow admin access if the user is admin OR if we're masquerading
        // (the real user must be admin to have started the masquerade).
        guard user.isAdmin || context.realUserID != nil else {
            throw HTTPError(.forbidden)
        }
        self.coreContext = context.coreContext
        self.user = user
        self.flashMessages = context.flashMessages
        self.masqueradingAs = context.masqueradingAs
        self.realUserID = context.realUserID
    }
}
