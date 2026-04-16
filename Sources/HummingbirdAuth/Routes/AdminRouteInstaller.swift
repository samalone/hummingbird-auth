import FluentKit
import Foundation
import Hummingbird
import HummingbirdAuthCore
import Logging

// Decodable types must be at module scope in Swift 6 (not nested in generic closures).
struct RoleInput: Decodable { var role: String }
struct InviteInput: Decodable {
    var email: String?
    var expires_days: Int?
}

/// Configuration for admin routes.
public struct AdminRouteConfiguration: Sendable {
    /// Base URL for generating invitation links (e.g., "http://localhost:8080").
    public var baseURL: String
    /// Session cookie name (must match SessionConfiguration.cookieName).
    public var cookieName: String
    /// Invitation configuration for creating new invitations.
    public var invitations: InvitationConfiguration

    public init(
        baseURL: String = "http://localhost:8080",
        cookieName: String = "session",
        invitations: InvitationConfiguration = .init()
    ) {
        self.baseURL = baseURL
        self.cookieName = cookieName
        self.invitations = invitations
    }
}

/// Install admin routes for user management, invitation management, and masquerade.
///
/// All routes require admin access (AdminContext).
///
/// - `GET /admin/users` — user list
/// - `POST /admin/users/:id/role` — change user role
/// - `POST /admin/users/:id/masquerade` — start masquerade
/// - `POST /admin/masquerade/end` — end masquerade
/// - `GET /admin/invitations` — invitation list
/// - `POST /admin/invitations` — create invitation
/// - `POST /admin/invitations/:id/delete` — delete unused invitation
///
/// The `renderUsers` and `renderInvitations` closures receive view model
/// arrays and should return a `ResponseGenerator` (typically `HTML` pages).
public func installAdminRoutes<Context: AuthRequestContextProtocol, UsersPage: ResponseGenerator, InvitationsPage: ResponseGenerator>(
    on router: RouterGroup<AdminContext<Context>>,
    db: Database,
    logger: Logger,
    config: AdminRouteConfiguration,
    renderUsers: @escaping @Sendable ([AdminUserViewModel], AdminContext<Context>) -> UsersPage,
    renderInvitations: @escaping @Sendable ([AdminInvitationViewModel], String, AdminContext<Context>) -> InvitationsPage
) where Context.User: FluentAuthUser {

    // MARK: - User Management

    router.get("/admin/users") { request, context -> Response in
        let users = try await Context.User.query(on: db).all()
            .sorted { ($0.createdAt ?? .distantPast) < ($1.createdAt ?? .distantPast) }

        let viewModels = users.map { user in
            AdminUserViewModel(
                id: user.id!,
                displayName: user.displayName,
                email: user.email,
                isAdmin: user.isAdmin,
                createdAt: user.createdAt
            )
        }

        return try renderUsers(viewModels, context).response(from: request, context: context)
    }

    router.post("/admin/users/:id/role") { request, context -> Response in
        guard let id = context.parameters.get("id", as: UUID.self),
              var user = try await Context.User.find(id, on: db) else {
            throw HTTPError(.notFound)
        }

        // Prevent self-demotion.
        let currentUserID = context.realUserID ?? context.user.id
        guard id != currentUserID else {
            throw HTTPError(.badRequest, message: "Cannot change your own role")
        }

        let input = try await URLEncodedFormDecoder().decode(
            RoleInput.self, from: request, context: context
        )

        user.isAdmin = input.role == "admin"
        try await user.save(on: db)

        return .redirect(to: "/admin/users", type: .normal)
    }

    // MARK: - Masquerade

    router.post("/admin/users/:id/masquerade") { request, context -> Response in
        guard let targetID = context.parameters.get("id", as: UUID.self),
              let _ = try await Context.User.find(targetID, on: db) else {
            throw HTTPError(.notFound)
        }

        let adminID = context.realUserID ?? context.user.id!

        guard let token = request.cookies[config.cookieName]?.value,
              let session = try await AuthSession.query(on: db)
                .filter(\.$token == token)
                .first()
        else {
            throw HTTPError(.unauthorized)
        }

        session.masqueradeUserID = targetID
        session.realUserID = adminID
        try await session.save(on: db)

        return .redirect(to: "/", type: .normal)
    }

    router.post("/admin/masquerade/end") { request, context -> Response in
        guard let token = request.cookies[config.cookieName]?.value,
              let session = try await AuthSession.query(on: db)
                .filter(\.$token == token)
                .first(),
              session.realUserID != nil
        else {
            throw HTTPError(.badRequest, message: "Not masquerading")
        }

        session.masqueradeUserID = nil
        session.realUserID = nil
        try await session.save(on: db)

        return .redirect(to: "/admin/users", type: .normal)
    }

    // MARK: - Invitation Management

    router.get("/admin/invitations") { request, context -> Response in
        let invitations = try await Invitation.query(on: db)
            .sort(\.$createdAt, .descending)
            .all()

        let viewModels = invitations.map { inv in
            AdminInvitationViewModel(
                id: inv.id!,
                email: inv.email,
                token: inv.token,
                expiresAt: inv.expiresAt,
                createdAt: inv.createdAt,
                isConsumed: inv.consumedAt != nil
            )
        }

        return try renderInvitations(viewModels, config.baseURL, context).response(from: request, context: context)
    }

    router.post("/admin/invitations") { request, context -> Response in
        let input = try await URLEncodedFormDecoder().decode(
            InviteInput.self, from: request, context: context
        )

        let email = input.email?.trimmingCharacters(in: .whitespacesAndNewlines)
        let invitationService = InvitationService(
            db: db, logger: logger,
            config: InvitationConfiguration(
                tokenTTL: TimeInterval(input.expires_days ?? 7) * 86400
            )
        )

        _ = try await invitationService.createInvitation(
            email: email?.isEmpty == true ? nil : email,
            invitedByID: context.realUserID ?? context.user.id
        )

        return .redirect(to: "/admin/invitations", type: .normal)
    }

    router.post("/admin/invitations/:id/delete") { _, context -> Response in
        guard let id = context.parameters.get("id", as: UUID.self),
              let invitation = try await Invitation.find(id, on: db) else {
            throw HTTPError(.notFound)
        }
        guard invitation.consumedAt == nil else {
            throw HTTPError(.badRequest, message: "Cannot delete a consumed invitation")
        }
        try await invitation.delete(on: db)
        return .redirect(to: "/admin/invitations", type: .normal)
    }
}
