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
///     init(source: ApplicationRequestContextSource) { ... }
/// }
/// ```
public protocol AuthRequestContextProtocol: RequestContext {
    associatedtype User: AuthUser

    /// The authenticated user, if any. Set by SessionMiddleware.
    var user: User? { get set }

    /// Flash messages consumed from the session.
    var flashMessages: [FlashMessage] { get set }
}

/// Child context for routes requiring an authenticated user.
///
/// Usage:
/// ```swift
/// let authed = router.group(context: AuthenticatedContext<AppContext>.self)
/// authed.get("/profile") { request, context -> HTML in
///     let user = context.user  // Non-optional
///     ...
/// }
/// ```
public struct AuthenticatedContext<Parent: AuthRequestContextProtocol>: ChildRequestContext, Sendable {
    public typealias ParentContext = Parent

    public var coreContext: CoreRequestContextStorage
    public let user: Parent.User
    public let flashMessages: [FlashMessage]

    public init(context: Parent) throws {
        guard let user = context.user else {
            throw HTTPError(.unauthorized)
        }
        self.coreContext = context.coreContext
        self.user = user
        self.flashMessages = context.flashMessages
    }
}

/// Child context for routes requiring admin access.
///
/// Throws 401 if not authenticated, 403 if not an admin.
public struct AdminContext<Parent: AuthRequestContextProtocol>: ChildRequestContext, Sendable {
    public typealias ParentContext = Parent

    public var coreContext: CoreRequestContextStorage
    public let user: Parent.User
    public let flashMessages: [FlashMessage]

    public init(context: Parent) throws {
        guard let user = context.user else {
            throw HTTPError(.unauthorized)
        }
        guard user.isAdmin else {
            throw HTTPError(.forbidden)
        }
        self.coreContext = context.coreContext
        self.user = user
        self.flashMessages = context.flashMessages
    }
}
