import Plot
import PlotHTMX

/// Embeddable login form component with a passkey button.
///
/// Wrap this in your app's PageLayout and include `WebAuthnScript.scriptTag`
/// in the page's `<head>`.
///
/// ```swift
/// router.get("/login") { request, context -> HTML in
///     PageLayout(title: "Sign In") {
///         LoginView(pathPrefix: "/auth")
///     }.html
/// }
/// ```
public struct LoginView: Component {
    /// Optional error message to display above the button.
    public var errorMessage: String?
    /// URL to redirect to after successful login (defaults to "/").
    public var returnURL: String?
    /// The auth API path prefix (must match `AuthConfiguration.pathPrefix`).
    public var pathPrefix: String

    public init(
        errorMessage: String? = nil,
        returnURL: String? = nil,
        pathPrefix: String = "/auth"
    ) {
        self.errorMessage = errorMessage
        self.returnURL = returnURL
        self.pathPrefix = pathPrefix
    }

    public var body: Component {
        Div {
            if let error = errorMessage {
                Div { Paragraph(error) }.class("auth-error")
            }

            Div {}
                .attribute(named: "id", value: "auth-error-message")
                .class("auth-error")
                .hidden(true)

            Node.input(.type(.hidden), .id("auth-return-url"), .value(returnURL ?? "/"))

            Element(name: "button") {
                Text("Sign in with Passkey")
            }
            .attribute(named: "id", value: "auth-login-button")
            .type("button")
            .class("auth-button primary")
        }
        .class("auth-login-view")
        .attribute(named: "data-auth-prefix", value: pathPrefix)
    }
}
