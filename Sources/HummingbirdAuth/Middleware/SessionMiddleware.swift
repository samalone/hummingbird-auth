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

        if let token = request.cookies[config.cookieName]?.value {
            if let session = try await AuthSession.query(on: db)
                .filter(\.$token == token)
                .filter(\.$expiresAt > Date())
                .first()
            {
                let effectiveUserID = session.masqueradeUserID ?? session.userID
                if let user = try await Context.User.find(effectiveUserID, on: db) {
                    context.user = user

                    // Populate masquerade state.
                    if session.masqueradeUserID != nil, let realID = session.realUserID {
                        context.masqueradingAs = user.displayName
                        context.realUserID = realID
                    }
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
        maxAge: Int = 30 * 86400,
        secure: Bool = true,
        cookieName: String = "session"
    ) -> Cookie {
        Cookie(
            name: cookieName,
            value: token,
            maxAge: maxAge,
            path: "/",
            secure: secure,
            httpOnly: true,
            sameSite: .lax
        )
    }

    /// Create an expired session cookie (for logout).
    public static func expiredAuthSession(cookieName: String = "session") -> Cookie {
        Cookie(
            name: cookieName,
            value: "deleted",
            maxAge: 0,
            path: "/"
        )
    }
}
