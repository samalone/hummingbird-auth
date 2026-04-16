import HummingbirdAuthCore
import Plot
import PlotHTMX

/// Embeddable profile editing form component.
///
/// Renders a display name and email form. Wrap in your app's PageLayout.
public struct ProfileView: Component {
    public var viewModel: ProfileViewModel

    public init(viewModel: ProfileViewModel) {
        self.viewModel = viewModel
    }

    public var body: Component {
        Div {
            if let msg = viewModel.savedMessage {
                Div { Paragraph(msg) }.class("flash-message flash-success")
            }

            Element(name: "form") {
                Node.input(.type(.hidden), .name("csrf_token"),
                           .value(viewModel.csrfToken ?? ""))
                Div {
                    Element(name: "label") { Text("Display Name") }
                        .attribute(named: "for", value: "display_name")
                    Node.input(.name("display_name"), .id("display_name"),
                               .value(viewModel.displayName))
                        .attribute(named: "type", value: "text")
                        .required()
                }
                .class("form-field")

                Div {
                    Element(name: "label") { Text("Email") }
                        .attribute(named: "for", value: "email")
                    Node.input(.name("email"), .id("email"),
                               .value(viewModel.email))
                        .attribute(named: "type", value: "email")
                        .required()
                }
                .class("form-field")

                Div {
                    Element(name: "button") { Text("Save") }
                        .type("submit")
                        .class("auth-button primary")
                }
                .class("form-actions")
            }
            .attribute(named: "method", value: "POST")
            .attribute(named: "action", value: "/profile")
        }
        .class("auth-profile-view")
    }
}
