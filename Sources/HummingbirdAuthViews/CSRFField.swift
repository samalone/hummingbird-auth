import HummingbirdAuthCore
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
            .name(csrfFormFieldName),
            .value(csrfToken ?? "")
        )
    }
}

/// `<meta name="csrf-token" content="...">` tag used by `CSRFHTMXScript`
/// and by app-side JavaScript to locate the current session's CSRF token.
///
/// Include this in the `<head>` of any authenticated page that will issue
/// non-GET requests via HTMX, `fetch()`, or XHR.
///
/// ```swift
/// .head(
///     ...
///     csrfMetaTag(context.csrfToken),
///     .raw(CSRFHTMXScript.scriptTag)
/// )
/// ```
public func csrfMetaTag(_ csrfToken: String?) -> Node<HTML.HeadContext> {
    .meta(.name("csrf-token"), .content(csrfToken ?? ""))
}
