import FluentKit
import Foundation
import Hummingbird
import HummingbirdAuth
import HummingbirdAuthCore

/// Protocol extending `CSRFProtectedContext` with OAuth-specific fields.
///
/// The CSRF refinement is inherited because `installOAuthRoutes` mounts
/// state-changing endpoints (token exchange, dynamic registration,
/// consent) that live under cookie authentication. Bearer-authenticated
/// API traffic is exempt from CSRF by `CSRFMiddleware`'s bearer-auth skip
/// condition.
public protocol OAuthRequestContextProtocol: CSRFProtectedContext {
    var oauthScopes: Set<String> { get set }
    var oauthClientID: UUID? { get set }
}

/// Validates OAuth Bearer tokens and populates the request context.
///
/// Session-based auth takes priority — if a user is already in the context
/// (from SessionMiddleware), the Bearer token is ignored.
public struct OAuthBearerMiddleware<Context: OAuthRequestContextProtocol>: RouterMiddleware
where Context.User: FluentAuthUser {
    private let oauthService: OAuthService
    private let db: Database

    public init(oauthService: OAuthService) {
        self.oauthService = oauthService
        self.db = oauthService.db
    }

    public func handle(
        _ request: Request,
        context: Context,
        next: (Request, Context) async throws -> Response
    ) async throws -> Response {
        var context = context

        if context.user == nil,
           let authHeader = request.headers[.authorization],
           authHeader.lowercased().hasPrefix("bearer ") {
            let token = String(authHeader.dropFirst(7))
            if let result = try await oauthService.validateAccessToken(token) {
                if let user = try await Context.User.find(result.userID, on: db) {
                    context.user = user
                    context.oauthScopes = result.scopes
                    context.oauthClientID = result.clientID
                }
            }
        }

        return try await next(request, context)
    }
}
