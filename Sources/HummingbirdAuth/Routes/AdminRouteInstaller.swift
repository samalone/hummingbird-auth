import FluentKit
import Foundation
import Hummingbird
import HummingbirdAuthCore
import Logging

// Decodable types must be at module scope in Swift 6 (not nested in generic closures).
struct RoleInput: Decodable { var role: String; var csrf_token: String }
struct MasqueradeInput: Decodable { var csrf_token: String }
struct InviteInput: Decodable {
    var email: String?
    var expires_days: Int?
    var csrf_token: String
}
struct DeleteInput: Decodable { var csrf_token: String }

/// Configuration for admin routes.
public struct AdminRouteConfiguration: Sendable {
    /// Base URL for generating invitation links (e.g., "http://localhost:8080").
    public var baseURL: String
    /// Invitation configuration for creating new invitations.
    public var invitations: InvitationConfiguration

    public init(
        baseURL: String = "http://localhost:8080",
        invitations: InvitationConfiguration = .init()
    ) {
        self.baseURL = baseURL
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
/// Routes land under whatever `RouterGroup` is passed in. Internal redirects
/// use `context.mountPath` from `AuthRequestContextProtocol` (default `""`),
/// which apps mounted on a sub-path should set to that prefix.
///
/// The `renderUsers` and `renderInvitations` closures receive view model
/// arrays and should return a `ResponseGenerator` (typically `HTML` pages).
///
/// Optional `renderUserRow` and `renderInvitationList` closures enable HTMX
/// partial-swap responses. When provided, write handlers that succeed inspect
/// the `HX-Request` header and respond with a rendered fragment instead of
/// a redirect:
///
/// - `POST /admin/users/:id/role` — responds with the re-rendered user row
///   (typically a `<tr>`) for HTMX requests when `renderUserRow` is provided.
/// - `POST /admin/invitations` and `POST /admin/invitations/:id/delete` —
///   respond with the re-rendered invitation list for HTMX requests when
///   `renderInvitationList` is provided.
///
/// Masquerade start/end handlers always redirect (full navigation is the
/// right UX there), even for HTMX requests.
///
/// Validation-failure paths (e.g. "At least one admin must remain") keep
/// the existing flash-and-redirect behavior regardless of HTMX.
public func installAdminRoutes<
    Context: AuthRequestContextProtocol,
    UsersPage: ResponseGenerator,
    InvitationsPage: ResponseGenerator,
    UserRowFragment: ResponseGenerator,
    InvitationListFragment: ResponseGenerator
>(
    on router: RouterGroup<AdminContext<Context>>,
    db: Database,
    logger: Logger,
    config: AdminRouteConfiguration,
    renderUsers: @escaping @Sendable ([AdminUserViewModel], AdminContext<Context>) -> UsersPage,
    renderInvitations: @escaping @Sendable ([AdminInvitationViewModel], String, AdminContext<Context>) -> InvitationsPage,
    renderUserRow: (@Sendable (AdminUserViewModel, AdminContext<Context>) -> UserRowFragment)? = nil,
    renderInvitationList: (@Sendable ([AdminInvitationViewModel], String, AdminContext<Context>) -> InvitationListFragment)? = nil
) where Context.User: FluentAuthUser {
    installAdminRoutesImpl(
        on: router, db: db, logger: logger, config: config,
        renderUsers: renderUsers, renderInvitations: renderInvitations,
        renderUserRow: renderUserRow, renderInvitationList: renderInvitationList
    )
}

/// Overload for callers that do not supply HTMX fragment renderers.
public func installAdminRoutes<
    Context: AuthRequestContextProtocol,
    UsersPage: ResponseGenerator,
    InvitationsPage: ResponseGenerator
>(
    on router: RouterGroup<AdminContext<Context>>,
    db: Database,
    logger: Logger,
    config: AdminRouteConfiguration,
    renderUsers: @escaping @Sendable ([AdminUserViewModel], AdminContext<Context>) -> UsersPage,
    renderInvitations: @escaping @Sendable ([AdminInvitationViewModel], String, AdminContext<Context>) -> InvitationsPage
) where Context.User: FluentAuthUser {
    let noUserRow: (@Sendable (AdminUserViewModel, AdminContext<Context>) -> Response)? = nil
    let noInvitationList: (@Sendable ([AdminInvitationViewModel], String, AdminContext<Context>) -> Response)? = nil
    installAdminRoutesImpl(
        on: router, db: db, logger: logger, config: config,
        renderUsers: renderUsers, renderInvitations: renderInvitations,
        renderUserRow: noUserRow, renderInvitationList: noInvitationList
    )
}

/// Shared implementation of `installAdminRoutes`.
private func installAdminRoutesImpl<
    Context: AuthRequestContextProtocol,
    UsersPage: ResponseGenerator,
    InvitationsPage: ResponseGenerator,
    UserRowFragment: ResponseGenerator,
    InvitationListFragment: ResponseGenerator
>(
    on router: RouterGroup<AdminContext<Context>>,
    db: Database,
    logger: Logger,
    config: AdminRouteConfiguration,
    renderUsers: @escaping @Sendable ([AdminUserViewModel], AdminContext<Context>) -> UsersPage,
    renderInvitations: @escaping @Sendable ([AdminInvitationViewModel], String, AdminContext<Context>) -> InvitationsPage,
    renderUserRow: (@Sendable (AdminUserViewModel, AdminContext<Context>) -> UserRowFragment)?,
    renderInvitationList: (@Sendable ([AdminInvitationViewModel], String, AdminContext<Context>) -> InvitationListFragment)?
) where Context.User: FluentAuthUser {

    // MARK: - User Management

    router.get("/admin/users") { request, context -> Response in
        let users = try await Context.User.query(on: db).all()
            .sorted { ($0.createdAt ?? .distantPast) < ($1.createdAt ?? .distantPast) }

        let viewModels = try users.map { try AdminUserViewModel(from: $0) }

        return try renderUsers(viewModels, context).response(from: request, context: context)
    }

    router.post("/admin/users/:id/role") { request, context -> Response in
        guard let id = context.parameters.get("id", as: UUID.self),
              var user = try await Context.User.find(id, on: db) else {
            throw HTTPError(.notFound)
        }

        let input = try await URLEncodedFormDecoder().decode(
            RoleInput.self, from: request, context: context
        )
        try validateCSRFToken(submitted: input.csrf_token, expected: context.csrfToken)

        // For validation failures that are user-visible (not developer
        // errors like CSRF or not-found), attach a flash message and
        // redirect back to /admin/users so browsers see an HTML page
        // rather than a JSON error blob.
        func bail(_ message: String) async throws -> Response {
            guard let token = request.cookies[SessionConfiguration.cookieName]?.value,
                  let session = try await AuthSession.query(on: db)
                    .filter(\.$token == token)
                    .first()
            else {
                throw HTTPError(.badRequest, message: message)
            }
            session.addFlash(.error, message)
            try await session.save(on: db)
            return .redirect(to: "\(context.mountPath)/admin/users", type: .normal)
        }

        // Prevent self-demotion.
        let currentUserID = context.realUserID ?? context.user.id
        if id == currentUserID {
            return try await bail("Cannot change your own role")
        }

        let makeAdmin = input.role == "admin"

        // Enforce "at least one admin" invariant: if we're demoting the
        // last remaining admin, refuse. Guards against two admins
        // demoting each other down to zero and against a crafted POST
        // bypassing the disabled UI button.
        if user.isAdmin && !makeAdmin {
            let adminCount = try await Context.User.countAdmins(on: db)
            if adminCount <= 1 {
                return try await bail("At least one admin must remain")
            }
        }

        user.isAdmin = makeAdmin
        try await user.save(on: db)

        let fragment = try renderUserRow.map { try $0(AdminUserViewModel(from: user), context) }
        return try htmxFragmentOrRedirect(
            fragment: { fragment },
            isHTMX: isHTMXRequest(request),
            redirectTo: "\(context.mountPath)/admin/users",
            request: request,
            context: context
        )
    }

    // MARK: - Masquerade

    router.post("/admin/users/:id/masquerade") { request, context -> Response in
        let input = try await URLEncodedFormDecoder().decode(
            MasqueradeInput.self, from: request, context: context
        )
        try validateCSRFToken(submitted: input.csrf_token, expected: context.csrfToken)

        guard let targetID = context.parameters.get("id", as: UUID.self),
              let _ = try await Context.User.find(targetID, on: db) else {
            throw HTTPError(.notFound)
        }

        let adminID = context.realUserID ?? context.user.id!

        guard let token = request.cookies[SessionConfiguration.cookieName]?.value,
              let session = try await AuthSession.query(on: db)
                .filter(\.$token == token)
                .first()
        else {
            throw HTTPError(.unauthorized)
        }

        session.masqueradeUserID = targetID
        session.realUserID = adminID
        try await session.save(on: db)

        // After starting a masquerade, send the admin to the app's
        // landing page (the mount path, or "/" if mounted at root).
        let landing = context.mountPath.isEmpty ? "/" : context.mountPath
        return .redirect(to: landing, type: .normal)
    }

    router.post("/admin/masquerade/end") { request, context -> Response in
        let input = try await URLEncodedFormDecoder().decode(
            MasqueradeInput.self, from: request, context: context
        )
        try validateCSRFToken(submitted: input.csrf_token, expected: context.csrfToken)

        guard let token = request.cookies[SessionConfiguration.cookieName]?.value,
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

        return .redirect(to: "\(context.mountPath)/admin/users", type: .normal)
    }

    // MARK: - Invitation Management

    router.get("/admin/invitations") { request, context -> Response in
        let viewModels = try await fetchInvitationViewModels(db: db)
        return try renderInvitations(viewModels, config.baseURL, context).response(from: request, context: context)
    }

    router.post("/admin/invitations") { request, context -> Response in
        let input = try await URLEncodedFormDecoder().decode(
            InviteInput.self, from: request, context: context
        )
        try validateCSRFToken(submitted: input.csrf_token, expected: context.csrfToken)

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

        let isHTMX = isHTMXRequest(request)
        let viewModels = isHTMX && renderInvitationList != nil
            ? try await fetchInvitationViewModels(db: db)
            : []
        return try htmxFragmentOrRedirect(
            fragment: { renderInvitationList?(viewModels, config.baseURL, context) },
            isHTMX: isHTMX,
            redirectTo: "\(context.mountPath)/admin/invitations",
            request: request,
            context: context
        )
    }

    router.post("/admin/invitations/:id/delete") { request, context -> Response in
        let input = try await URLEncodedFormDecoder().decode(
            DeleteInput.self, from: request, context: context
        )
        try validateCSRFToken(submitted: input.csrf_token, expected: context.csrfToken)

        guard let id = context.parameters.get("id", as: UUID.self),
              let invitation = try await Invitation.find(id, on: db) else {
            throw HTTPError(.notFound)
        }
        guard invitation.consumedAt == nil else {
            throw HTTPError(.badRequest, message: "Cannot delete a consumed invitation")
        }
        try await invitation.delete(on: db)

        let isHTMX = isHTMXRequest(request)
        let viewModels = isHTMX && renderInvitationList != nil
            ? try await fetchInvitationViewModels(db: db)
            : []
        return try htmxFragmentOrRedirect(
            fragment: { renderInvitationList?(viewModels, config.baseURL, context) },
            isHTMX: isHTMX,
            redirectTo: "\(context.mountPath)/admin/invitations",
            request: request,
            context: context
        )
    }
}

/// If the request came from HTMX and the caller supplied a fragment, render
/// the fragment as the response; otherwise fall back to a redirect.
private func htmxFragmentOrRedirect<Fragment: ResponseGenerator>(
    fragment: () throws -> Fragment?,
    isHTMX: Bool,
    redirectTo: String,
    request: Request,
    context: some RequestContext
) throws -> Response {
    if isHTMX, let fragment = try fragment() {
        return try fragment.response(from: request, context: context)
    }
    return .redirect(to: redirectTo, type: .normal)
}

extension AdminUserViewModel {
    /// Build a view model from a Fluent-backed user. The user must have been
    /// loaded from the database (or just saved), so `id` is non-nil.
    init<U: FluentAuthUser>(from user: U) throws {
        self.init(
            id: try user.requireID(),
            displayName: user.displayName,
            email: user.email,
            isAdmin: user.isAdmin,
            createdAt: user.createdAt
        )
    }
}

/// Fetch all invitations and map them to view models, ordered newest-first.
/// Shared by the index handler and the HTMX partial-swap responses.
private func fetchInvitationViewModels(db: Database) async throws -> [AdminInvitationViewModel] {
    let invitations = try await Invitation.query(on: db)
        .sort(\.$createdAt, .descending)
        .all()

    return invitations.map { inv in
        AdminInvitationViewModel(
            id: inv.id!,
            email: inv.email,
            token: inv.token,
            expiresAt: inv.expiresAt,
            createdAt: inv.createdAt,
            isConsumed: inv.consumedAt != nil
        )
    }
}
