import Foundation
import HummingbirdAuthCore
import Plot
import PlotHTMX

/// Embeddable admin invitation management component.
///
/// Renders an invitation creation form and a table of existing invitations
/// with copy URL and delete actions.
///
/// HTMX: the create form and each delete form carry `hx-post` /
/// `hx-target="#admin-invitations-list"` / `hx-swap="outerHTML"` so a
/// configured server can respond with a re-rendered list fragment via
/// `AdminInvitationList`. Plain `<form method="POST">` is retained as a
/// progressive-enhancement fallback.
public struct AdminInvitationsView: Component {
    public var invitations: [AdminInvitationViewModel]
    public var baseURL: String
    public var csrfToken: String?
    /// Prefix prepended to form action URLs (the app's mount path, e.g.
    /// `"/prospero"`, or `""` when mounted at root).
    public var pathPrefix: String

    public init(
        invitations: [AdminInvitationViewModel],
        baseURL: String,
        csrfToken: String? = nil,
        pathPrefix: String = ""
    ) {
        self.invitations = invitations
        self.baseURL = baseURL
        self.csrfToken = csrfToken
        self.pathPrefix = pathPrefix
    }

    public var body: Component {
        Div {
            // Create form
            Element(name: "form") {
                Node.input(.type(.hidden), .name("csrf_token"),
                           .value(csrfToken ?? ""))
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
            .attribute(named: "action", value: "\(pathPrefix)/admin/invitations")
            .hxPost("\(pathPrefix)/admin/invitations")
            .hxTarget("#admin-invitations-list")
            .hxSwap(.outerHTML)
            .class("invite-form")

            AdminInvitationList(
                invitations: invitations,
                baseURL: baseURL,
                csrfToken: csrfToken,
                pathPrefix: pathPrefix
            )
        }
        .class("auth-admin-invitations-view")
    }
}

/// The invitation table on its own, identified by `id="admin-invitations-list"`
/// so HTMX can swap it after create/delete. Exposed so route handlers can
/// re-render the list as a fragment.
public struct AdminInvitationList: Component {
    public var invitations: [AdminInvitationViewModel]
    public var baseURL: String
    public var csrfToken: String?
    public var pathPrefix: String

    public init(
        invitations: [AdminInvitationViewModel],
        baseURL: String,
        csrfToken: String? = nil,
        pathPrefix: String = ""
    ) {
        self.invitations = invitations
        self.baseURL = baseURL
        self.csrfToken = csrfToken
        self.pathPrefix = pathPrefix
    }

    private static var dateFormatter: DateFormatter {
        let f = DateFormatter()
        f.dateFormat = "MMM d, yyyy h:mm a"
        return f
    }

    public var body: Component {
        Div {
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
                                            Node.input(.type(.hidden), .name("csrf_token"),
                                                       .value(csrfToken ?? ""))
                                            Element(name: "button") { Text("Delete") }
                                                .type("submit")
                                                .class("button small danger")
                                        }
                                        .attribute(named: "method", value: "POST")
                                        .attribute(named: "action", value: "\(pathPrefix)/admin/invitations/\(inv.id)/delete")
                                        .hxPost("\(pathPrefix)/admin/invitations/\(inv.id)/delete")
                                        .hxTarget("#admin-invitations-list")
                                        .hxSwap(.outerHTML)
                                    }
                                }
                            }
                        }
                    }
                }
                .class("data-table")
            }
        }
        .id("admin-invitations-list")
        .class("admin-invitations-list")
    }
}
