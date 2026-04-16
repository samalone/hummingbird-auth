import Foundation
import HummingbirdAuthCore
import Plot
import PlotHTMX

/// Embeddable admin user list component.
///
/// Renders a table of users with role management and masquerade buttons.
public struct AdminUsersView: Component {
    public var users: [AdminUserViewModel]

    public init(users: [AdminUserViewModel]) {
        self.users = users
    }

    private static let dateFormatter: DateFormatter = {
        let f = DateFormatter()
        f.dateFormat = "MMM d, yyyy"
        return f
    }()

    public var body: Component {
        Div {
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
                                        Node.input(.type(.hidden), .name("role"),
                                                   .value(user.isAdmin ? "user" : "admin"))
                                        Element(name: "button") {
                                            Text(user.isAdmin ? "Remove admin" : "Make admin")
                                        }
                                        .type("submit")
                                        .class("button small secondary")
                                    }
                                    .attribute(named: "method", value: "POST")
                                    .attribute(named: "action", value: "/admin/users/\(user.id)/role")

                                    Element(name: "form") {
                                        Element(name: "button") { Text("Masquerade") }
                                            .type("submit")
                                            .class("button small secondary")
                                    }
                                    .attribute(named: "method", value: "POST")
                                    .attribute(named: "action", value: "/admin/users/\(user.id)/masquerade")
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
