import Crypto
import Foundation
import HTTPTypes
import Hummingbird
import HummingbirdAuthCore
import NIOCore

extension HTTPField.Name {
    /// The `X-CSRF-Token` header used by `CSRFMiddleware` for HTMX /
    /// fetch / XHR / JSON / multipart requests that can't (or don't want
    /// to) carry the token in a form body.
    public static let csrfToken = HTTPField.Name("X-CSRF-Token")!
}

/// Enforces CSRF protection for state-changing, cookie-authenticated requests.
///
/// The synchronizer-token-pattern already used by `SessionMiddleware` is
/// sufficient: every session carries a `csrfToken` that is embedded in the
/// session cookie-protected pages. State-changing requests must echo that
/// token back either in a form field named `csrf_token` or in an
/// `X-CSRF-Token` header.
///
/// ### Skip conditions
///
/// The middleware intentionally does nothing for requests that have nothing
/// to forge against:
///
/// - Safe methods (`GET`, `HEAD`, `OPTIONS`).
/// - Requests authenticated by an OAuth bearer token — those are not
///   cookie-authenticated, so CSRF does not apply.
/// - Requests that arrive without a session cookie (unauthenticated).
/// - Requests explicitly marked by the `SkipCSRF` middleware for an
///   opt-out group (webhooks, metrics, etc.).
///
/// ### Where to read the token
///
/// - `application/x-www-form-urlencoded` bodies: read `csrf_token` from
///   the collected, URL-decoded form body. The collected body is
///   re-attached to the request so downstream handlers can decode it
///   normally.
/// - Any other content type (including `multipart/form-data`, JSON,
///   HTMX / fetch / XHR requests): require the `X-CSRF-Token` header.
///
/// ### Ordering
///
/// Install after `SessionMiddleware` (and after `OAuthBearerMiddleware`
/// when using the OAuth layer). The middleware needs the session's
/// `csrfToken` populated on the context to compare against.
///
/// ```swift
/// router.add(middleware: SessionMiddleware<AppContext>(db: db))
/// router.add(middleware: CSRFMiddleware<AppContext>())
/// ```
///
/// Opt-out routes must be installed *outside* the group that applies
/// `CSRFMiddleware`, or have `SkipCSRF` applied at a layer that runs
/// *before* `CSRFMiddleware`. See `SkipCSRF` for details.
public struct CSRFMiddleware<Context: CSRFProtectedContext>: RouterMiddleware {
    /// Maximum number of body bytes this middleware will collect when
    /// parsing a form-urlencoded body for the `csrf_token` field.
    private let maxFormBodySize: Int

    /// Name of the form field that carries the CSRF token.
    public static var formFieldName: String { "csrf_token" }

    /// Name of the HTTP request header that carries the CSRF token.
    public static var headerName: String { "X-CSRF-Token" }

    public init(maxFormBodySize: Int = 1024 * 1024) {
        self.maxFormBodySize = maxFormBodySize
    }

    public func handle(
        _ request: Request,
        context: Context,
        next: (Request, Context) async throws -> Response
    ) async throws -> Response {
        var request = request
        var context = context

        // Explicit opt-out (SkipCSRF middleware).
        if context.csrfSkipped {
            context.csrfValidated = true
            return try await next(request, context)
        }

        // Safe methods never mutate state.
        switch request.method {
        case .get, .head, .options:
            context.csrfValidated = true
            return try await next(request, context)
        default:
            break
        }

        // Unauthenticated requests (no session cookie) have nothing to
        // forge against. The route, if it requires authentication, will
        // reject on its own.
        if request.cookies[SessionConfiguration.cookieName] == nil {
            context.csrfValidated = true
            return try await next(request, context)
        }

        // OAuth bearer-authenticated requests. The OAuth bearer layer is
        // optional; detect it via the `Authorization: Bearer …` header.
        // Note: `OAuthBearerMiddleware` only populates the user when no
        // session user is present, but bearer requests to cookie-protected
        // apps might arrive with both. A bearer token by itself is enough
        // to skip CSRF — the token is the authenticator.
        if let authHeader = request.headers[.authorization],
           authHeader.lowercased().hasPrefix("bearer ") {
            context.csrfValidated = true
            return try await next(request, context)
        }

        // Validate.
        let expected = context.csrfToken
        let submitted: String? = try await extractToken(from: &request)
        guard let expected, let submitted,
              constantTimeEquals(expected, submitted)
        else {
            throw HTTPError(.forbidden, message: "Invalid CSRF token")
        }

        context.csrfValidated = true
        return try await next(request, context)
    }

    /// Pull a token out of either the `X-CSRF-Token` header or the
    /// form body. For form bodies the collected bytes are re-attached
    /// to the request so downstream handlers can decode as usual.
    private func extractToken(from request: inout Request) async throws -> String? {
        // Header first — simplest, and the only valid source for JSON,
        // HTMX, fetch, XHR, and multipart.
        if let header = request.headers[.csrfToken] {
            return header
        }

        // Only try the body when it's form-urlencoded.
        let contentType = request.headers[.contentType] ?? ""
        guard contentType.lowercased()
            .hasPrefix("application/x-www-form-urlencoded")
        else {
            return nil
        }

        let buffer = try await request.collectBody(upTo: maxFormBodySize)
        let formString = String(buffer: buffer)
        return parseFormField(
            Self.formFieldName, from: formString
        )
    }

    /// Very small URL-encoded form parser that returns the first match
    /// for a given field name. Percent-decodes both sides.
    private func parseFormField(_ name: String, from formString: String) -> String? {
        for pair in formString.split(separator: "&") {
            let parts = pair.split(separator: "=", maxSplits: 1)
            guard parts.count == 2 else { continue }
            let rawKey = String(parts[0])
            let rawValue = String(parts[1])
            let key = rawKey
                .replacingOccurrences(of: "+", with: " ")
                .removingPercentEncoding ?? rawKey
            if key == name {
                let value = rawValue
                    .replacingOccurrences(of: "+", with: " ")
                    .removingPercentEncoding ?? rawValue
                return value
            }
        }
        return nil
    }

    /// Constant-time string compare. Prevents timing attacks on token
    /// comparison. Both strings are converted to `Data` and fed through
    /// `HashedAuthenticationCode`-style comparison via
    /// `swift-crypto`'s `SymmetricKey`-agnostic primitive.
    private func constantTimeEquals(_ a: String, _ b: String) -> Bool {
        let aView = a.utf8
        let bView = b.utf8
        if aView.count != bView.count { return false }
        var diff: UInt8 = 0
        for (byteA, byteB) in zip(aView, bView) {
            diff |= byteA ^ byteB
        }
        return diff == 0
    }
}

