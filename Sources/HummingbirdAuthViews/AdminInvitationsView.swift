import Foundation
import HummingbirdAuthCore
import Plot
import PlotHTMX

/// Embeddable admin invitation management component.
///
/// Renders an invitation creation form and a table of existing invitations
/// with copy URL and delete actions.
public struct AdminInvitationsView: Component {
    public var invitations: [AdminInvitationViewModel]
    public var baseURL: String

    public init(invitations: [AdminInvitationViewModel], baseURL: String) {
        self.invitations = invitations
        self.baseURL = baseURL
    }

    private static let dateFormatter: DateFormatter = {
        let f = DateFormatter()
        f.dateFormat = "MMM d, yyyy h:mm a"
        return f
    }()

    public var body: Component {
        Div {
            // Create form
            Element(name: "form") {
                Div {
                    Div {
                        Element(name: "label") { Text("Email (optional)") }
                            .attribute(named: "for", value: "email")
                        Node.input(.name("email"), .id("email"),
                                   .placeholder("invitee@example.com"))
                            .attribute(named: "type", value: "email")
                    }
                    .class("form-field")

                    Div {
                        Element(name: "label") { Text("Expires in (days)") }
                            .attribute(named: "for", value: "expires_days")
                        Node.input(.name("expires_days"), .id("expires_days"), .value("7"))
                            .attribute(named: "type", value: "number")
                            .attribute(named: "min", value: "1")
                            .attribute(named: "max", value: "30")
                    }
                    .class("form-field")
                }
                .class("form-row")
                Element(name: "button") { Text("Create Invitation") }
                    .type("submit")
                    .class("auth-button primary")
            }
            .attribute(named: "method", value: "POST")
            .attribute(named: "action", value: "/admin/invitations")
            .class("invite-form")

            if !invitations.isEmpty {
                Element(name: "table") {
                    Element(name: "thead") {
                        Element(name: "tr") {
                            Element(name: "th") { Text("Email") }
                            Element(name: "th") { Text("URL") }
                            Element(name: "th") { Text("Expires") }
                            Element(name: "th") { Text("Status") }
                            Element(name: "th") { Text("Actions") }
                        }
                    }
                    Element(name: "tbody") {
                        for inv in invitations {
                            let url = "\(baseURL)/invite/\(inv.token)"
                            Element(name: "tr") {
                                Element(name: "td") { Text(inv.email ?? "Anyone") }
                                Element(name: "td") {
                                    Element(name: "code") { Text(String(inv.token.prefix(12))) }
                                        .title(url)
                                    Text(" ")
                                    Element(name: "button") { Text("Copy") }
                                        .type("button")
                                        .class("button small secondary")
                                        .on("click", "navigator.clipboard.writeText('\(url)');this.textContent='Copied!'")
                                }
                                Element(name: "td") {
                                    Text(Self.dateFormatter.string(from: inv.expiresAt))
                                }
                                Element(name: "td") {
                                    Text(inv.isConsumed ? "Used" : "Pending")
                                }
                                Element(name: "td") {
                                    if !inv.isConsumed {
                                        Element(name: "form") {
                                            Element(name: "button") { Text("Delete") }
                                                .type("submit")
                                                .class("button small danger")
                                        }
                                        .attribute(named: "method", value: "POST")
                                        .attribute(named: "action", value: "/admin/invitations/\(inv.id)/delete")
                                    }
                                }
                            }
                        }
                    }
                }
                .class("data-table")
            }
        }
        .class("auth-admin-invitations-view")
    }
}
