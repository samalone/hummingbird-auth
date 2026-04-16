import HTTPTypes
import Hummingbird

/// Catches 401 errors on HTML requests and redirects to the login page.
/// Passes through 401 unchanged for API requests (JSON Accept or Content-Type,
/// or HTMX requests).
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
                || isHTMX(request)
            {
                throw error
            }
            // HTML requests redirect to login with return URL.
            let returnTo = request.uri.description
                .addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? ""
            return .redirect(to: "\(loginPath)?return=\(returnTo)")
        }
    }

    private func isHTMX(_ request: Request) -> Bool {
        request.headers[HTTPField.Name("HX-Request")!] != nil
    }
}
