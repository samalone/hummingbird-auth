import Foundation
import Hummingbird
import HummingbirdAuthCore

/// Middleware that opts a route out of `CSRFMiddleware`'s enforcement.
///
/// ### When to use
///
/// Rarely. Most state-changing routes that sit behind a session cookie
/// need CSRF protection. Legitimate opt-out cases include:
///
/// - External webhook receivers (the peer has no session cookie and
///   authenticates with a shared secret or signature header).
/// - Metrics / healthcheck endpoints that mutate nothing.
/// - Routes authenticated exclusively by `OAuthBearerMiddleware` that
///   nevertheless live alongside cookie routes (normally the middleware's
///   bearer-auth check handles these, but if the bearer layer isn't
///   installed you can use this marker).
///
/// ### Placement
///
/// `SkipCSRF` must run *before* `CSRFMiddleware` so the flag is visible
/// when `CSRFMiddleware` checks it. In Hummingbird, middleware added to
/// an outer group runs before middleware added to an inner group. The
/// recommended pattern is to apply `CSRFMiddleware` to the group of
/// routes that need it and leave opt-out routes outside that group:
///
/// ```swift
/// // CSRF-protected routes:
/// let protected = router.group(middleware: CSRFMiddleware<AppContext>())
/// installAuthRoutes(on: protected, db: db, config: cfg, logger: logger)
///
/// // Opt-out: webhooks sit outside the protected group.
/// let webhooks = router.group(middleware: SkipCSRF<AppContext>())
/// webhooks.post("/webhooks/stripe") { request, context in /* ... */ }
/// ```
///
/// If you must install `CSRFMiddleware` globally (i.e. via
/// `router.add(middleware:)`) and still opt out a subset of routes,
/// restructure so the opt-out group wraps `CSRFMiddleware` (outer
/// `SkipCSRF` → inner group with `CSRFMiddleware`). The simpler pattern
/// above is preferred.
public struct SkipCSRF<Context: CSRFProtectedContext>: RouterMiddleware {
    public init() {}

    public func handle(
        _ request: Request,
        context: Context,
        next: (Request, Context) async throws -> Response
    ) async throws -> Response {
        var context = context
        context.csrfSkipped = true
        return try await next(request, context)
    }
}
