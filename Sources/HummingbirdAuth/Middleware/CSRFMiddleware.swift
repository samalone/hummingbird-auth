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
    public static let csrfToken = HTTPField.Name(csrfHeaderName)!
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
///   the collected, URL-decoded form body. Hummingbird's
///   `collectBody(upTo:)` buffers the body back onto `request.body`, so
///   downstream `URLEncodedFormDecoder` calls can still decode it.
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
    /// Kept as a public constant for caller reference; the internal form
    /// decoder hard-codes the name via the `CSRFEnvelope` property below.
    public static var formFieldName: String { csrfFormFieldName }

    /// Name of the HTTP request header that carries the CSRF token.
    public static var headerName: String { csrfHeaderName }

    public init(maxFormBodySize: Int = 1024 * 1024) {
        self.maxFormBodySize = maxFormBodySize
    }

    public func handle(
        _ request: Request,
        context: Context,
        next: (Request, Context) async throws -> Response
    ) async throws -> Response {
        var request = request

        // Explicit opt-out (SkipCSRF middleware).
        if context.csrfSkipped {
            return try await next(request, context)
        }

        // Safe methods never mutate state.
        switch request.method {
        case .get, .head, .options:
            return try await next(request, context)
        default:
            break
        }

        // Unauthenticated requests (no session cookie) have nothing to
        // forge against. The route, if it requires authentication, will
        // reject on its own.
        if request.cookies[SessionConfiguration.cookieName] == nil {
            return try await next(request, context)
        }

        // OAuth bearer-authenticated requests. The OAuth bearer layer is
        // optional; detect it via the `Authorization: Bearer …` header.
        // Note: `OAuthBearerMiddleware` only populates the user when no
        // session user is present, but bearer requests to cookie-protected
        // apps might arrive with both. A bearer token by itself is enough
        // to skip CSRF — the token is the authenticator.
        if let authHeader = request.headers[.authorization],
           authHeader.hasCaseInsensitiveASCIIPrefix("bearer ") {
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

        return try await next(request, context)
    }

    /// Envelope used to decode the form body for just the CSRF field.
    /// Additional form fields present in the body are ignored.
    private struct CSRFEnvelope: Decodable {
        // swiftlint:disable:next identifier_name
        var csrf_token: String?
    }

    /// Pull a token out of either the `X-CSRF-Token` header or the
    /// form body. For form-urlencoded bodies `collectBody(upTo:)` buffers
    /// the body back onto `request.body`, so downstream decoders can still
    /// read it.
    private func extractToken(from request: inout Request) async throws -> String? {
        // Header first — simplest, and the only valid source for JSON,
        // HTMX, fetch, XHR, and multipart.
        if let header = request.headers[.csrfToken] {
            return header
        }

        // Only try the body when it's form-urlencoded.
        let contentType = request.headers[.contentType] ?? ""
        guard contentType.hasCaseInsensitiveASCIIPrefix("application/x-www-form-urlencoded")
        else {
            return nil
        }

        let buffer = try await request.collectBody(upTo: maxFormBodySize)
        let formString = String(buffer: buffer)
        return extractCSRFField(from: formString)
    }

    /// Decode the `csrf_token` field out of a URL-encoded form body
    /// using Hummingbird's decoder. Returns `nil` if the field is absent
    /// or the body is malformed.
    private func extractCSRFField(from formString: String) -> String? {
        (try? URLEncodedFormDecoder().decode(CSRFEnvelope.self, from: formString))?.csrf_token
    }

    /// Constant-time byte comparison — XOR-accumulate to avoid early-exit
    /// timing leaks that a plain `==` comparison would leak via branch
    /// timing on the first differing byte.
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

// MARK: - String helpers

extension String {
    /// Case-insensitive (ASCII) prefix check that avoids allocating a
    /// full lowercased copy of the receiver. Compares only as many
    /// bytes as `prefix.utf8.count`. Intended for header inspection in
    /// hot paths where callers previously used `lowercased().hasPrefix(…)`.
    fileprivate func hasCaseInsensitiveASCIIPrefix(_ prefix: String) -> Bool {
        let selfBytes = self.utf8
        let prefixBytes = prefix.utf8
        if selfBytes.count < prefixBytes.count { return false }
        for (a, b) in zip(selfBytes, prefixBytes) {
            // Lowercase ASCII A–Z → a–z by setting bit 0x20. Non-letters
            // are passed through unchanged, which is fine for the small
            // set of tokens we compare ("bearer ",
            // "application/x-www-form-urlencoded").
            let lowerA = (a >= 0x41 && a <= 0x5A) ? a | 0x20 : a
            let lowerB = (b >= 0x41 && b <= 0x5A) ? b | 0x20 : b
            if lowerA != lowerB { return false }
        }
        return true
    }
}

