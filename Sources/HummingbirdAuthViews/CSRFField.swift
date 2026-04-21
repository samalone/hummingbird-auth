import Plot

/// Embeddable hidden CSRF form field.
///
/// Include this inside any state-changing form that posts to a
/// cookie-authenticated endpoint. The `CSRFMiddleware` on the server
/// rejects POST/PATCH/DELETE requests whose `csrf_token` doesn't match
/// the current session's token, so forms that forget to include this
/// field fail loudly with a 403 — not silently.
///
/// ```swift
/// Element(name: "form") {
///     CSRFField(context.csrfToken)
///     // … other inputs …
/// }
/// ```
///
/// `csrfToken` may be `nil` for unauthenticated requests, in which case
/// the field is rendered with an empty value. `CSRFMiddleware` does not
/// enforce CSRF on unauthenticated requests, so an empty token for a
/// login-form render is fine.
public struct CSRFField: Component {
    public let csrfToken: String?

    public init(_ csrfToken: String?) {
        self.csrfToken = csrfToken
    }

    public var body: Component {
        Node.input(
            .type(.hidden),
            .name("csrf_token"),
            .value(csrfToken ?? "")
        )
    }
}

/// Build the JSON object that HTMX's `hx-headers` attribute expects in
/// order to add an `X-CSRF-Token` header to a request.
///
/// Use this on HTMX elements that trigger non-GET requests which don't
/// naturally carry a form body (`hx-post`, `hx-delete`, `hx-patch` with
/// JSON, etc.):
///
/// ```swift
/// Element(name: "button") { Text("Delete") }
///     .attribute(named: "hx-delete", value: "/items/\(id)")
///     .attribute(named: "hx-headers", value: hxCSRFHeaders(context.csrfToken))
/// ```
///
/// Returns an empty object (`{}`) when `csrfToken` is nil — HTMX will
/// treat that as "no extra headers" rather than failing, and
/// `CSRFMiddleware` will reject the resulting request if it's a
/// state-changing, cookie-authenticated request.
public func hxCSRFHeaders(_ csrfToken: String?) -> String {
    guard let csrfToken else { return "{}" }
    // Minimal JSON-escape: escape " and \ which are the only legal
    // characters in the token that would break the JSON string. Session
    // CSRF tokens are hex-encoded, so in practice neither appears, but
    // the escape is cheap and future-proofs against format changes.
    let escaped = csrfToken
        .replacingOccurrences(of: "\\", with: "\\\\")
        .replacingOccurrences(of: "\"", with: "\\\"")
    return "{\"X-CSRF-Token\":\"\(escaped)\"}"
}
