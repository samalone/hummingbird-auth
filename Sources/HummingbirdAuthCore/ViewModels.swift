// View models shared between the Auth (route installers create them)
// and Views (Plot components consume them) targets.

import Foundation

/// View model for the profile page.
public struct ProfileViewModel: Sendable {
    public var displayName: String
    public var email: String
    public var savedMessage: String?
    public var csrfToken: String?

    public init(displayName: String, email: String, savedMessage: String? = nil, csrfToken: String? = nil) {
        self.displayName = displayName
        self.email = email
        self.savedMessage = savedMessage
        self.csrfToken = csrfToken
    }
}

/// View model for a user in the admin user list.
public struct AdminUserViewModel: Sendable {
    public var id: UUID
    public var displayName: String
    public var email: String
    public var isAdmin: Bool
    public var createdAt: Date?

    public init(id: UUID, displayName: String, email: String, isAdmin: Bool, createdAt: Date?) {
        self.id = id
        self.displayName = displayName
        self.email = email
        self.isAdmin = isAdmin
        self.createdAt = createdAt
    }
}

/// View model for an invitation in the admin invitation list.
public struct AdminInvitationViewModel: Sendable {
    public var id: UUID
    public var email: String?
    public var token: String
    public var expiresAt: Date
    public var createdAt: Date?
    public var isConsumed: Bool

    public init(id: UUID, email: String?, token: String, expiresAt: Date, createdAt: Date?, isConsumed: Bool) {
        self.id = id
        self.email = email
        self.token = token
        self.expiresAt = expiresAt
        self.createdAt = createdAt
        self.isConsumed = isConsumed
    }
}
