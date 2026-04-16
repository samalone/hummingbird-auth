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
public struct SessionConfiguration: Sendable {
    public var cookieName: String
    public var sessionTTL: TimeInterval
    public var secureCookie: Bool

    public init(
        cookieName: String = "session",
        sessionTTL: TimeInterval = 86400 * 30,
        secureCookie: Bool = true
    ) {
        self.cookieName = cookieName
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

    /// Called after a new user is registered.
    public var onUserRegistered: (@Sendable (U) async throws -> Void)?

    /// Called after a user logs in.
    public var onUserLoggedIn: (@Sendable (U) async throws -> Void)?

    public init(
        postLoginRedirect: @Sendable @escaping (U) -> String = { _ in "/" },
        postLogoutRedirect: String = "/login",
        onUserRegistered: (@Sendable (U) async throws -> Void)? = nil,
        onUserLoggedIn: (@Sendable (U) async throws -> Void)? = nil
    ) {
        self.postLoginRedirect = postLoginRedirect
        self.postLogoutRedirect = postLogoutRedirect
        self.onUserRegistered = onUserRegistered
        self.onUserLoggedIn = onUserLoggedIn
    }
}
