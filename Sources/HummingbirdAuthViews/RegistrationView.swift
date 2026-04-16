import Plot
import PlotHTMX

/// Embeddable registration form component with passkey creation.
///
/// Wrap this in your app's PageLayout and include `WebAuthnScript.scriptTag`
/// in the page's `<head>`.
///
/// ```swift
/// router.get("/invite/:token") { request, context -> HTML in
///     PageLayout(title: "Create Account") {
///         RegistrationView(invitationToken: token, pathPrefix: "/auth")
///     }.html
/// }
/// ```
public struct RegistrationView: Component {
    /// The invitation token (passed as a hidden field).
    public var invitationToken: String
    /// Pre-filled email from the invitation (if any).
    public var email: String?
    /// Optional error message to display.
    public var errorMessage: String?
    /// The auth API path prefix.
    public var pathPrefix: String

    public init(
        invitationToken: String,
        email: String? = nil,
        errorMessage: String? = nil,
        pathPrefix: String = "/auth"
    ) {
        self.invitationToken = invitationToken
        self.email = email
        self.errorMessage = errorMessage
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

            Element(name: "form") {
                Div {
                    Element(name: "label") { Text("Display Name") }
                        .attribute(named: "for", value: "auth-display-name")
                    Node.input(
                        .id("auth-display-name"),
                        .name("displayName"),
                        .attribute(named: "autocomplete", value: "name"),
                        .placeholder("Your name")
                    )
                    .attribute(named: "type", value: "text")
                    .required()
                }
                .class("form-field")

                Div {
                    Element(name: "label") { Text("Email") }
                        .attribute(named: "for", value: "auth-email")
                    Node.input(
                        .id("auth-email"),
                        .name("email"),
                        .attribute(named: "autocomplete", value: "email"),
                        .placeholder("you@example.com"),
                        .value(email ?? "")
                    )
                    .attribute(named: "type", value: "email")
                    .required()
                }
                .class("form-field")

                Node.input(
                    .type(.hidden),
                    .id("auth-invitation-token"),
                    .name("invitationToken"),
                    .value(invitationToken)
                )

                Element(name: "button") {
                    Text("Create Account with Passkey")
                }
                .type("submit")
                .class("auth-button primary")
            }
            .attribute(named: "id", value: "auth-registration-form")
        }
        .class("auth-registration-view")
        .attribute(named: "data-auth-prefix", value: pathPrefix)
    }
}
