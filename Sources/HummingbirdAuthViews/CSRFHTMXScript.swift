import HummingbirdAuthCore

/// Adds the `X-CSRF-Token` header to every HTMX request automatically.
///
/// Uses HTMX's `htmx:configRequest` event — the canonical extension point
/// for decorating outgoing HTMX requests. The listener reads the token
/// from `<meta name="csrf-token">` (emit with `csrfMetaTag(_:)`) so the
/// same page-level source of truth is shared with plain `fetch()` callers.
///
/// Include in the `<head>` of every authenticated page that issues HTMX
/// mutations (`hx-post`, `hx-patch`, `hx-delete`, etc.):
///
/// ```swift
/// .head(
///     ...
///     csrfMetaTag(context.csrfToken),
///     .raw(CSRFHTMXScript.scriptTag)
/// )
/// ```
///
/// Works for both static HTMX attributes and elements added dynamically
/// after page load.
public enum CSRFHTMXScript {

    /// The complete listener source.
    public static let source: String = """
    (function() {
        document.addEventListener('htmx:configRequest', function (e) {
            var meta = document.querySelector('meta[name="csrf-token"]');
            var token = meta ? meta.getAttribute('content') || '' : '';
            if (token) {
                e.detail.headers['\(csrfHeaderName)'] = token;
            }
        });
    })();
    """

    /// A `<script>` tag containing the listener.
    /// Use with `.raw()` in Plot's Node DSL.
    public static let scriptTag: String = "<script>\(source)</script>"
}
