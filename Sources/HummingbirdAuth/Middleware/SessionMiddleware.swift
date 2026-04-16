import FluentKit
import Foundation
import Hummingbird
import HummingbirdAuthCore

/// Reads the session cookie, loads the session and user, and populates
/// the request context.
///
/// The `Context.User` type must conform to both `AuthUser` and Fluent's `Model`
/// so that sessions can look up users by UUID.
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
                }

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
