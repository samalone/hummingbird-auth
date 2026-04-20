import Foundation

/// Top-level configuration for the hummingbird-auth library.
public struct AuthConfiguration<U: AuthUser>: Sendable {
    /// Passkey/WebAuthn configuration.
    public var passkey: PasskeyConfiguration

    /// Session management configuration.
    public var session: SessionConfiguration

    /// Invitation configuration. Nil disables invitation-based registration.
    public var invitations: InvitationConfiguration?

    /// Path prefix for auth API routes (default: "/auth").
    public var pathPrefix: String

    /// Path for the login page (default: "/login").
    public var loginPagePath: String

    /// Path prefix for invitation pages (default: "/invite").
    public var invitePagePath: String

    /// Callbacks for app-specific behavior.
    public var callbacks: AuthCallbacks<U>

    public init(
        passkey: PasskeyConfiguration,
        session: SessionConfiguration = .init(),
        invitations: InvitationConfiguration? = nil,
        pathPrefix: String = "/auth",
        loginPagePath: String = "/login",
        invitePagePath: String = "/invite",
        callbacks: AuthCallbacks<U> = .init()
    ) {
        self.passkey = passkey
        self.session = session
        self.invitations = invitations
        self.pathPrefix = pathPrefix
        self.loginPagePath = loginPagePath
        self.invitePagePath = invitePagePath
        self.callbacks = callbacks
    }
}

/// WebAuthn relying party configuration.
public struct PasskeyConfiguration: Sendable {
    public var relyingPartyID: String
    public var relyingPartyName: String
    public var relyingPartyOrigin: String
    public var challengeTTL: TimeInterval

    public init(
        relyingPartyID: String,
        relyingPartyName: String,
        relyingPartyOrigin: String,
        challengeTTL: TimeInterval = 300
    ) {
        self.relyingPartyID = relyingPartyID
        self.relyingPartyName = relyingPartyName
        self.relyingPartyOrigin = relyingPartyOrigin
        self.challengeTTL = challengeTTL
    }
}

/// Session cookie and TTL configuration.
///
/// The cookie name is fixed as `hb-auth` to avoid synchronization issues
/// between middleware and route handlers. Cookie path scoping separates
/// sessions when multiple apps share a domain with path-based routing.
public struct SessionConfiguration: Sendable {
    /// Fixed cookie name used by the library.
    public static let cookieName = "hb-auth"

    /// Cookie path — scope the session cookie to this path prefix.
    ///
    /// Set this to your app's ingress path when running multiple apps
    /// behind the same domain (e.g., "/prospero"). Defaults to "/" which
    /// sends the cookie on all requests to the domain.
    public var cookiePath: String

    /// Session TTL in seconds. Default: 30 days.
    public var sessionTTL: TimeInterval

    /// Whether to set the Secure flag on the cookie. Default: true.
    public var secureCookie: Bool

    public init(
        cookiePath: String = "/",
        sessionTTL: TimeInterval = 86400 * 30,
        secureCookie: Bool = true
    ) {
        self.cookiePath = cookiePath
        self.sessionTTL = sessionTTL
        self.secureCookie = secureCookie
    }
}

/// Invitation token configuration.
public struct InvitationConfiguration: Sendable {
    public var tokenTTL: TimeInterval

    public init(tokenTTL: TimeInterval = 86400 * 7) {
        self.tokenTTL = tokenTTL
    }
}

/// Callbacks that let apps customize auth behavior.
public struct AuthCallbacks<U: AuthUser>: Sendable {
    /// Where to redirect after successful login. Default: "/"
    public var postLoginRedirect: @Sendable (U) -> String

    /// Where to redirect after logout. Default: "/login"
    public var postLogoutRedirect: String

    /// Called after a user successfully registers via an invitation.
    /// Receives the newly-created user *and* a `ConsumedInvitation` DTO
    /// snapshot of the invitation that was consumed during registration.
    /// Apps can use the DTO's metadata (id, email, invitedByID) to apply
    /// invitation-specific side effects — e.g. creating a task-share row
    /// for a share-link invitation. The DTO is a plain Swift struct so
    /// this callback's signature does not require a Fluent dependency.
    public var onUserRegistered: (@Sendable (U, ConsumedInvitation) async throws -> Void)?

    /// Called after a user logs in.
    public var onUserLoggedIn: (@Sendable (U) async throws -> Void)?

    public init(
        postLoginRedirect: @Sendable @escaping (U) -> String = { _ in "/" },
        postLogoutRedirect: String = "/login",
        onUserRegistered: (@Sendable (U, ConsumedInvitation) async throws -> Void)? = nil,
        onUserLoggedIn: (@Sendable (U) async throws -> Void)? = nil
    ) {
        self.postLoginRedirect = postLoginRedirect
        self.postLogoutRedirect = postLogoutRedirect
        self.onUserRegistered = onUserRegistered
        self.onUserLoggedIn = onUserLoggedIn
    }
}
