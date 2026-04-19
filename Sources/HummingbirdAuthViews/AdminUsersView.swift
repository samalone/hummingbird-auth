import Foundation
import HummingbirdAuthCore
import Plot
import PlotHTMX

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
public struct AdminUsersView: Component {
    public var users: [AdminUserViewModel]
    public var csrfToken: String?
    /// Prefix prepended to form action URLs (the app's mount path, e.g.
    /// `"/prospero"`, or `""` when mounted at root).
    public var pathPrefix: String
    /// ID of the currently-viewing admin, used to hide self-targeting
    /// actions. Pass `nil` to leave all actions visible.
    public var currentUserID: UUID?

    public init(
        users: [AdminUserViewModel],
        csrfToken: String? = nil,
        pathPrefix: String = "",
        currentUserID: UUID? = nil
    ) {
        self.users = users
        self.csrfToken = csrfToken
        self.pathPrefix = pathPrefix
        self.currentUserID = currentUserID
    }

    private static let dateFormatter: DateFormatter = {
        let f = DateFormatter()
        f.dateFormat = "MMM d, yyyy"
        return f
    }()

    public var body: Component {
        // Disable "Remove admin" everywhere when only one admin remains.
        let adminCount = users.lazy.filter(\.isAdmin).count
        let onlyOneAdmin = adminCount <= 1

        return Div {
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
                        let isSelf = currentUserID != nil && user.id == currentUserID
                        let demotingLastAdmin = user.isAdmin && onlyOneAdmin
                        Element(name: "tr") {
                            Element(name: "td") { Text(user.displayName) }
                            Element(name: "td") { Text(user.email) }
                            Element(name: "td") {
                                Element(name: "span") {
                                    Text(user.isAdmin ? "Admin" : "User")
                                }
                                .class(user.isAdmin ? "role-badge role-admin" : "role-badge")
                            }
                            Element(name: "td") {
                                Text(user.createdAt.map { Self.dateFormatter.string(from: $0) } ?? "")
                            }
                            Element(name: "td") {
                                Div {
                                    Element(name: "form") {
                                        Node.input(.type(.hidden), .name("csrf_token"),
                                                   .value(csrfToken ?? ""))
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
                                                    : ""
                                            )
                                    }
                                    .attribute(named: "method", value: "POST")
                                    .attribute(named: "action", value: "\(pathPrefix)/admin/users/\(user.id)/role")

                                    if !isSelf {
                                        Element(name: "form") {
                                            Node.input(.type(.hidden), .name("csrf_token"),
                                                       .value(csrfToken ?? ""))
                                            Element(name: "button") { Text("Masquerade") }
                                                .type("submit")
                                                .class("button small secondary")
                                        }
                                        .attribute(named: "method", value: "POST")
                                        .attribute(named: "action", value: "\(pathPrefix)/admin/users/\(user.id)/masquerade")
                                    }
                                }
                                .class("table-actions")
                            }
                        }
                    }
                }
            }
            .class("data-table")
        }
        .class("auth-admin-users-view")
    }
}
