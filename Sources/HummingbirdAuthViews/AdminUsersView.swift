import Foundation
import HummingbirdAuthCore
import Plot
import PlotHTMX

/// Shared date formatter for admin user rows.
///
/// `DateFormatter` is thread-safe for read-only use after configuration, so a
/// single shared instance is safe to reuse across renders.
private let adminUserRowDateFormatter: DateFormatter = {
    let f = DateFormatter()
    f.dateFormat = "MMM d, yyyy"
    return f
}()

/// Embeddable admin user list component.
///
/// Renders a table of users with role management and masquerade buttons.
///
/// Guardrails on the visible controls:
/// - The Masquerade button is omitted for the viewer's own row — you can't
///   masquerade as yourself.
/// - The "Remove admin" button is disabled when there's only one admin
///   account, so the system always has at least one. The backend should
///   enforce the same invariant independently.
///
/// The optional `preamble` lets embedding apps inject custom content above
/// the user table.
public struct AdminUsersView<Preamble: Component>: Component {
    public var users: [AdminUserViewModel]
    public var csrfToken: String?
    /// Prefix prepended to form action URLs (the app's mount path, e.g.
    /// `"/prospero"`, or `""` when mounted at root).
    public var pathPrefix: String
    /// ID of the currently-viewing admin, used to hide self-targeting
    /// actions. Pass `nil` to leave all actions visible.
    public var currentUserID: UUID?
    public var preamble: Preamble

    public init(
        users: [AdminUserViewModel],
        csrfToken: String? = nil,
        pathPrefix: String = "",
        currentUserID: UUID? = nil,
        @ComponentBuilder preamble: () -> Preamble = { EmptyComponent() }
    ) {
        self.users = users
        self.csrfToken = csrfToken
        self.pathPrefix = pathPrefix
        self.currentUserID = currentUserID
        self.preamble = preamble()
    }

    public var body: Component {
        // Disable "Remove admin" everywhere when only one admin remains.
        let adminCount = users.lazy.filter(\.isAdmin).count
        let onlyOneAdmin = adminCount <= 1

        return Div {
            preamble
            Element(name: "table") {
                Element(name: "thead") {
                    Element(name: "tr") {
                        Element(name: "th") { Text("Name") }
                        Element(name: "th") { Text("Email") }
                        Element(name: "th") { Text("Role") }
                        Element(name: "th") { Text("Joined") }
                        Element(name: "th") { Text("Actions") }
                    }
                }
                Element(name: "tbody") {
                    for user in users {
                        AdminUserRow(
                            user: user,
                            csrfToken: csrfToken,
                            pathPrefix: pathPrefix,
                            currentUserID: currentUserID,
                            onlyOneAdmin: onlyOneAdmin
                        )
                    }
                }
            }
            .class("data-table")
        }
        .class("auth-admin-users-view")
    }
}

/// A single row in the admin user table. Exposed so route handlers can
/// re-render a row for HTMX partial-swap responses.
public struct AdminUserRow: Component {
    public var user: AdminUserViewModel
    public var csrfToken: String?
    public var pathPrefix: String
    public var currentUserID: UUID?
    /// Pass `true` to disable "Remove admin" for this row (used when the
    /// user is the last remaining admin). Callers rendering a single row
    /// for an HTMX response can recompute this from the up-to-date user
    /// list.
    public var onlyOneAdmin: Bool

    public init(
        user: AdminUserViewModel,
        csrfToken: String? = nil,
        pathPrefix: String = "",
        currentUserID: UUID? = nil,
        onlyOneAdmin: Bool = false
    ) {
        self.user = user
        self.csrfToken = csrfToken
        self.pathPrefix = pathPrefix
        self.currentUserID = currentUserID
        self.onlyOneAdmin = onlyOneAdmin
    }

    public var body: Component {
        let isSelf = currentUserID != nil && user.id == currentUserID
        let demotingLastAdmin = user.isAdmin && onlyOneAdmin
        let rowID = "user-row-\(user.id)"

        return Element(name: "tr") {
            Element(name: "td") { Text(user.displayName) }
            Element(name: "td") { Text(user.email) }
            Element(name: "td") {
                Element(name: "span") {
                    Text(user.isAdmin ? "Admin" : "User")
                }
                .class(user.isAdmin ? "role-badge role-admin" : "role-badge")
            }
            Element(name: "td") {
                Text(user.createdAt.map { adminUserRowDateFormatter.string(from: $0) } ?? "")
            }
            Element(name: "td") {
                Div {
                    Element(name: "form") {
                        CSRFField(csrfToken)
                        Node.input(.type(.hidden), .name("role"),
                                   .value(user.isAdmin ? "user" : "admin"))
                        let roleButton = Element(name: "button") {
                            Text(user.isAdmin ? "Remove admin" : "Make admin")
                        }
                        .type("submit")
                        .class("button small secondary")
                        roleButton
                            .disabled(demotingLastAdmin)
                            .attribute(
                                named: "title",
                                value: demotingLastAdmin
                                    ? "At least one admin must remain."
                                    : nil
                            )
                    }
                    .attribute(named: "method", value: "POST")
                    .attribute(named: "action", value: "\(pathPrefix)/admin/users/\(user.id)/role")
                    .hxPost("\(pathPrefix)/admin/users/\(user.id)/role")
                    .hxTarget("#\(rowID)")
                    .hxSwap(.outerHTML)

                    if !isSelf {
                        Element(name: "form") {
                            CSRFField(csrfToken)
                            Element(name: "button") { Text("Masquerade") }
                                .type("submit")
                                .class("button small secondary")
                        }
                        .attribute(named: "method", value: "POST")
                        .attribute(named: "action", value: "\(pathPrefix)/admin/users/\(user.id)/masquerade")
                        // Masquerade must be a full navigation (it changes
                        // the effective user for the whole app), so do not
                        // add hx-* attributes here.
                    }
                }
                .class("table-actions")
            }
        }
        .id(rowID)
    }
}
