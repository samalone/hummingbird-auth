import FluentKit
import FluentSQLiteDriver
import Foundation
import HTTPTypes
import Hummingbird
import HummingbirdFluent
import HummingbirdTesting
import Logging
import NIOCore
import Plot
import Testing

@testable import HummingbirdAuth
@testable import HummingbirdAuthCore
@testable import HummingbirdAuthViews

// MARK: - Test user model

/// Minimal Fluent-backed user model used only by these tests.
final class TestUser: Model, AuthUser, @unchecked Sendable {
    static let schema = "users"

    @ID(key: .id)
    var id: UUID?

    @Field(key: "email")
    var email: String

    @Field(key: "display_name")
    var displayName: String

    @Field(key: "is_admin")
    var isAdmin: Bool

    @Timestamp(key: "created_at", on: .create)
    var createdAt: Date?

    init() {
        self.email = ""
        self.displayName = ""
        self.isAdmin = false
    }

    init(displayName: String, email: String) {
        self.email = email
        self.displayName = displayName
        self.isAdmin = false
    }

    init(email: String, displayName: String, isAdmin: Bool) {
        self.email = email
        self.displayName = displayName
        self.isAdmin = isAdmin
    }
}

extension TestUser: FluentAuthUser {
    static let emailFieldKey: FieldKey = "email"
}

struct CreateTestUsers: AsyncMigration {
    func prepare(on database: Database) async throws {
        try await database.schema(TestUser.schema)
            .id()
            .field("email", .string, .required)
            .field("display_name", .string, .required)
            .field("is_admin", .bool, .required, .sql(.default(false)))
            .field("created_at", .datetime)
            .unique(on: "email")
            .create()
    }

    func revert(on database: Database) async throws {
        try await database.schema(TestUser.schema).delete()
    }
}

// MARK: - Test context

struct TestContext: AuthRequestContextProtocol {
    typealias User = TestUser

    var coreContext: CoreRequestContextStorage
    var user: TestUser?
    var flashMessages: [FlashMessage] = []
    var masqueradingAs: String?
    var realUserID: UUID?
    var csrfToken: String?

    init(source: ApplicationRequestContextSource) {
        self.coreContext = .init(source: source)
    }
}

// MARK: - Test fixture

/// Everything a single HTMX route test needs.
struct AdminTestFixture {
    let fluent: Fluent
    let admin: TestUser
    let target: TestUser
    let sessionToken: String
    let csrfToken: String
}

/// Build the admin-router application and run the test closure with it.
///
/// The closure receives:
/// - the `TestClientProtocol` (as `any`, upcast at the call site)
/// - an `AdminTestFixture` with DB handle and seeded users/session
///
/// If `withFragmentRenderers` is true, the HTMX fragment closures are wired up.
private func withAdminApp(
    withFragmentRenderers: Bool,
    testBody: @Sendable (any TestClientProtocol, AdminTestFixture) async throws -> Void
) async throws {
    var logger = Logger(label: "hb-auth-admin-htmx-tests")
    logger.logLevel = .warning

    let fluent = Fluent(logger: logger)
    fluent.databases.use(.sqlite(.memory), as: .sqlite)
    await fluent.migrations.add(CreateTestUsers())
    await addAuthMigrations(to: fluent, userTable: TestUser.schema)
    try await fluent.migrate()

    let db = fluent.db()
    let admin = TestUser(email: "admin@example.com", displayName: "Admin", isAdmin: true)
    try await admin.save(on: db)
    let target = TestUser(email: "user@example.com", displayName: "Target", isAdmin: false)
    try await target.save(on: db)

    let sessionToken = UUID().uuidString
    let session = AuthSession(
        userID: try admin.requireID(),
        token: sessionToken,
        expiresAt: Date().addingTimeInterval(3600)
    )
    try await session.save(on: db)

    let fixture = AdminTestFixture(
        fluent: fluent, admin: admin, target: target,
        sessionToken: sessionToken, csrfToken: session.csrfToken
    )

    let router = Router(context: TestContext.self)
    router.add(middleware: SessionMiddleware<TestContext>(db: db))
    let adminGroup = router.group(context: AdminContext<TestContext>.self)

    let renderUsers: @Sendable ([AdminUserViewModel], AdminContext<TestContext>) -> Response = { _, _ in
        Response(status: .ok, headers: [:], body: .init(byteBuffer: ByteBuffer(string: "USERS_PAGE")))
    }
    let renderInvitations: @Sendable ([AdminInvitationViewModel], String, AdminContext<TestContext>) -> Response = { _, _, _ in
        Response(status: .ok, headers: [:], body: .init(byteBuffer: ByteBuffer(string: "INVITATIONS_PAGE")))
    }

    if withFragmentRenderers {
        let renderUserRow: @Sendable (AdminUserViewModel, AdminContext<TestContext>) -> Response = { vm, _ in
            let html = "<tr id=\"user-row-\(vm.id)\">FRAGMENT isAdmin=\(vm.isAdmin)</tr>"
            var headers = HTTPFields()
            headers[.contentType] = "text/html"
            return Response(status: .ok, headers: headers, body: .init(byteBuffer: ByteBuffer(string: html)))
        }
        let renderInvitationList: @Sendable ([AdminInvitationViewModel], String, AdminContext<TestContext>) -> Response = { list, _, _ in
            let html = "<div id=\"admin-invitations-list\">count=\(list.count)</div>"
            var headers = HTTPFields()
            headers[.contentType] = "text/html"
            return Response(status: .ok, headers: headers, body: .init(byteBuffer: ByteBuffer(string: html)))
        }
        installAdminRoutes(
            on: adminGroup, db: db, logger: logger,
            config: AdminRouteConfiguration(baseURL: "http://localhost"),
            renderUsers: renderUsers, renderInvitations: renderInvitations,
            renderUserRow: renderUserRow, renderInvitationList: renderInvitationList
        )
    } else {
        installAdminRoutes(
            on: adminGroup, db: db, logger: logger,
            config: AdminRouteConfiguration(baseURL: "http://localhost"),
            renderUsers: renderUsers, renderInvitations: renderInvitations
        )
    }

    var app = Application(
        router: router,
        configuration: .init(address: .hostname("127.0.0.1", port: 0)),
        logger: logger
    )
    app.addServices(fluent)

    do {
        try await app.test(.router) { client in
            try await testBody(client, fixture)
        }
    } catch {
        try? await fluent.shutdown()
        throw error
    }
    try await fluent.shutdown()
}

private let hxRequestHeader = HTTPField.Name("HX-Request")!

// MARK: - Route tests

@Suite("Admin route HTMX partials")
struct AdminRouteHTMXTests {

    @Test("POST /admin/users/:id/role with HX-Request + renderUserRow returns fragment")
    func htmxRoleChangeReturnsFragment() async throws {
        try await withAdminApp(withFragmentRenderers: true) { client, fx in
            let targetID = try fx.target.requireID()
            let body = "role=admin&csrf_token=\(fx.csrfToken)"
            try await client.execute(
                uri: "/admin/users/\(targetID)/role",
                method: .post,
                headers: [
                    .cookie: "\(SessionConfiguration.cookieName)=\(fx.sessionToken)",
                    .contentType: "application/x-www-form-urlencoded",
                    hxRequestHeader: "true",
                ],
                body: ByteBuffer(string: body)
            ) { response in
                #expect(response.status == .ok)
                let html = String(buffer: response.body)
                #expect(html.contains("user-row-\(targetID)"))
                #expect(html.contains("FRAGMENT"))
                #expect(html.contains("isAdmin=true"))
            }

            let updated = try await TestUser.find(targetID, on: fx.fluent.db())!
            #expect(updated.isAdmin)
        }
    }

    @Test("POST /admin/users/:id/role without HX-Request still redirects")
    func nonHtmxRoleChangeRedirects() async throws {
        try await withAdminApp(withFragmentRenderers: true) { client, fx in
            let targetID = try fx.target.requireID()
            let body = "role=admin&csrf_token=\(fx.csrfToken)"
            try await client.execute(
                uri: "/admin/users/\(targetID)/role",
                method: .post,
                headers: [
                    .cookie: "\(SessionConfiguration.cookieName)=\(fx.sessionToken)",
                    .contentType: "application/x-www-form-urlencoded",
                ],
                body: ByteBuffer(string: body)
            ) { response in
                #expect(response.status == .seeOther || response.status == .found)
                let location = response.headers[.location] ?? ""
                #expect(location == "/admin/users")
            }
        }
    }

    @Test("POST /admin/users/:id/role with HX-Request but no renderUserRow falls back to redirect")
    func htmxRoleChangeFallsBackToRedirect() async throws {
        try await withAdminApp(withFragmentRenderers: false) { client, fx in
            let targetID = try fx.target.requireID()
            let body = "role=admin&csrf_token=\(fx.csrfToken)"
            try await client.execute(
                uri: "/admin/users/\(targetID)/role",
                method: .post,
                headers: [
                    .cookie: "\(SessionConfiguration.cookieName)=\(fx.sessionToken)",
                    .contentType: "application/x-www-form-urlencoded",
                    hxRequestHeader: "true",
                ],
                body: ByteBuffer(string: body)
            ) { response in
                #expect(response.status == .seeOther || response.status == .found)
            }
        }
    }
}

// MARK: - View rendering tests

@Suite("Admin views")
struct AdminViewTests {
    @Test("AdminUsersView renders user rows with id=\"user-row-{uuid}\" and hx-* attributes")
    func userRowHasID() {
        let userID = UUID()
        let vm = AdminUserViewModel(
            id: userID,
            displayName: "Alice",
            email: "alice@example.com",
            isAdmin: false,
            createdAt: nil
        )
        let html = AdminUsersView(users: [vm]).render()
        #expect(html.contains("id=\"user-row-\(userID)\""))
        #expect(html.contains("hx-post=\"/admin/users/\(userID)/role\""))
        #expect(html.contains("hx-target=\"#user-row-\(userID)\""))
        #expect(html.contains("hx-swap=\"outerHTML\""))
    }

    @Test("AdminUsersView accepts a preamble")
    func preambleRenders() {
        let userID = UUID()
        let vm = AdminUserViewModel(
            id: userID, displayName: "Bob",
            email: "bob@example.com", isAdmin: false, createdAt: nil
        )
        let html = AdminUsersView(users: [vm]) {
            Element(name: "div") { Text("CUSTOM_PREAMBLE") }
                .class("custom-preamble")
        }.render()
        #expect(html.contains("CUSTOM_PREAMBLE"))
        #expect(html.contains("custom-preamble"))
    }

    @Test("AdminInvitationsView wraps list in id=\"admin-invitations-list\" container")
    func invitationListHasID() {
        let html = AdminInvitationsView(invitations: [], baseURL: "http://localhost").render()
        #expect(html.contains("id=\"admin-invitations-list\""))
        #expect(html.contains("hx-post=\"/admin/invitations\""))
        #expect(html.contains("hx-target=\"#admin-invitations-list\""))
    }
}
