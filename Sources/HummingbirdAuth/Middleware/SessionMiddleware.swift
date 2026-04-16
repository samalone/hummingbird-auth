import FluentKit
import Foundation
import Hummingbird
import HummingbirdAuthCore

/// Reads the session cookie, loads the session and user, and populates
/// the request context including masquerade state.
///
/// During masquerade, `context.user` is set to the *target* user,
/// `context.masqueradingAs` is the target's display name, and
/// `context.realUserID` is the admin's ID.
public struct SessionMiddleware<Context: AuthRequestContextProtocol>: RouterMiddleware
where Context.User: FluentAuthUser {
    private let db: Database
    private let config: SessionConfiguration

    public init(db: Database, config: SessionConfiguration = .init()) {
        self.db = db
        self.config = config
    }

    public func handle(
        _ request: Request,
        context: Context,
        next: (Request, Context) async throws -> Response
    ) async throws -> Response {
        var context = context

        if let token = request.cookies[SessionConfiguration.cookieName]?.value {
            if let session = try await AuthSession.query(on: db)
                .filter(\.$token == token)
                .filter(\.$expiresAt > Date())
                .first()
            {
                let effectiveUserID = session.masqueradeUserID ?? session.userID
                if let user = try await Context.User.find(effectiveUserID, on: db) {
                    // Populate masquerade state, but only if the real
                    // user is still an admin. If they were demoted
                    // mid-masquerade, end it silently.
                    if session.masqueradeUserID != nil, let realID = session.realUserID {
                        if let realUser = try await Context.User.find(realID, on: db),
                           realUser.isAdmin {
                            context.user = user
                            context.masqueradingAs = user.displayName
                            context.realUserID = realID
                        } else {
                            // Real user is no longer admin — end masquerade.
                            session.masqueradeUserID = nil
                            session.realUserID = nil
                            try await session.save(on: db)
                            // Load the original (real) user as the session owner.
                            if let originalUser = try await Context.User.find(session.userID, on: db) {
                                context.user = originalUser
                            }
                        }
                    } else {
                        context.user = user
                    }
                    context.csrfToken = session.csrfToken
                }

                // Consume flash messages (one-time display).
                let flashes = session.consumeFlashMessages()
                if !flashes.isEmpty {
                    context.flashMessages = flashes
                    try await session.save(on: db)
                }
            }
        }

        return try await next(request, context)
    }
}

// MARK: - Cookie Helpers

extension Cookie {
    /// Create a session cookie with SameSite=Lax.
    public static func authSession(
        token: String,
        config: SessionConfiguration
    ) -> Cookie {
        Cookie(
            name: SessionConfiguration.cookieName,
            value: token,
            maxAge: Int(config.sessionTTL),
            path: config.cookiePath,
            secure: config.secureCookie,
            httpOnly: true,
            sameSite: .lax
        )
    }

    /// Create an expired session cookie (for logout).
    /// Must use the same attributes as `authSession` so the browser
    /// matches and removes the correct cookie.
    public static func expiredAuthSession(config: SessionConfiguration) -> Cookie {
        Cookie(
            name: SessionConfiguration.cookieName,
            value: "deleted",
            maxAge: 0,
            path: config.cookiePath,
            secure: config.secureCookie,
            httpOnly: true,
            sameSite: .lax
        )
    }
}
