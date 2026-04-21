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

    /// CSRF token from the current session, for embedding in forms.
    var csrfToken: String? { get set }

    /// The path prefix under which the app is mounted, e.g. `"/prospero"`,
    /// or `""` when mounted at the domain root. Used by library handlers
    /// when they need to emit absolute redirect URLs that stay inside the app.
    ///
    /// Apps that mount their routes on a `router.group(RouterPath(prefix))`
    /// should expose the same prefix here. A default empty value is provided
    /// for apps mounted at root.
    var mountPath: String { get }
}

extension AuthRequestContextProtocol {
    public var mountPath: String { "" }
}

/// Marker refinement of `AuthRequestContextProtocol` that guarantees the
/// `CSRFMiddleware` has been installed and that the context carries the
/// per-request state it needs.
///
/// Route installers that mount state-changing endpoints
/// (`installAuthRoutes`, `installAdminRoutes`, `installProfileRoutes`,
/// `installOAuthRoutes`) constrain their `Context` parameter to
/// `CSRFProtectedContext`. Apps that don't install `CSRFMiddleware` receive
/// a compile error rather than a silently-insecure default.
///
/// ### Implementing the conformance
///
/// Add the CSRF stored properties to your app's context struct:
///
/// ```swift
/// struct AppContext: CSRFProtectedContext {
///     typealias User = AppUser
///     var coreContext: CoreRequestContextStorage
///     var user: AppUser?
///     var flashMessages: [FlashMessage] = []
///     var masqueradingAs: String?
///     var realUserID: UUID?
///     var csrfToken: String?
///     var csrfSkipped: Bool = false
///
///     init(source: ApplicationRequestContextSource) {
///         self.coreContext = .init(source: source)
///     }
/// }
/// ```
///
/// The `SkipCSRF` middleware sets `csrfSkipped = true` so `CSRFMiddleware`
/// honors the opt-out.
public protocol CSRFProtectedContext: AuthRequestContextProtocol {
    /// Opt-out flag set by the `SkipCSRF` middleware. `CSRFMiddleware`
    /// honors this and skips validation for routes that genuinely don't
    /// need it (webhooks, metrics endpoints, etc.). Use sparingly.
    var csrfSkipped: Bool { get set }
}

/// Child context for routes requiring an authenticated user.
public struct AuthenticatedContext<Parent: AuthRequestContextProtocol>: ChildRequestContext, Sendable {
    public typealias ParentContext = Parent

    public var coreContext: CoreRequestContextStorage
    public let user: Parent.User
    public let flashMessages: [FlashMessage]
    public let masqueradingAs: String?
    public let realUserID: UUID?
    public let csrfToken: String?
    public let mountPath: String

    public init(context: Parent) throws {
        guard let user = context.user else {
            throw HTTPError(.unauthorized)
        }
        self.coreContext = context.coreContext
        self.user = user
        self.flashMessages = context.flashMessages
        self.masqueradingAs = context.masqueradingAs
        self.realUserID = context.realUserID
        self.csrfToken = context.csrfToken
        self.mountPath = context.mountPath
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
    public let csrfToken: String?
    public let mountPath: String

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
        self.csrfToken = context.csrfToken
        self.mountPath = context.mountPath
    }
}
