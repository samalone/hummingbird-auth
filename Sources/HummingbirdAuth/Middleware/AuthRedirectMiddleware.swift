import HTTPTypes
import Hummingbird

extension HTTPField.Name {
    /// The `HX-Request` header HTMX sets on every request it initiates.
    public static let hxRequest = HTTPField.Name("HX-Request")!
}

/// Catches 401 errors on HTML requests and redirects to the login page.
/// Passes through 401 unchanged for API requests.
///
/// A request is classified as an API call (and gets the raw 401) if any of:
/// - `Accept` header contains `application/json`
/// - `Content-Type` header contains `application/json`
/// - `HX-Request` header is present (HTMX partial request)
///
/// This matters for WebAuthn ceremonies where `fetch()` sends JSON
/// with `Content-Type: application/json` but no `Accept` header.
public struct AuthRedirectMiddleware<Context: RequestContext>: RouterMiddleware {
    private let loginPath: String

    public init(loginPath: String = "/login") {
        self.loginPath = loginPath
    }

    public func handle(
        _ request: Request,
        context: Context,
        next: (Request, Context) async throws -> Response
    ) async throws -> Response {
        do {
            return try await next(request, context)
        } catch let error as HTTPError where error.status == .unauthorized {
            // API clients get the raw 401 — detect by Accept, Content-Type, or HTMX header.
            let accept = request.headers[.accept] ?? ""
            let contentType = request.headers[.contentType] ?? ""
            if accept.contains("application/json")
                || contentType.contains("application/json")
                || isHTMXRequest(request)
            {
                throw error
            }
            // HTML requests redirect to login with return URL.
            let returnTo = request.uri.description
                .addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? ""
            return .redirect(to: "\(loginPath)?return=\(returnTo)")
        }
    }
}

/// Returns `true` when the request was issued by HTMX (has an `HX-Request`
/// header). Used by route handlers to opt into fragment responses for
/// partial swaps instead of full-page redirects.
public func isHTMXRequest(_ request: Request) -> Bool {
    request.headers[.hxRequest] != nil
}
