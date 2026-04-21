import FluentKit
import FluentSQLiteDriver
import Foundation
import HTTPTypes
import Hummingbird
import HummingbirdFluent
import HummingbirdTesting
import Logging
import NIOCore
import Testing

@testable import HummingbirdAuth
@testable import HummingbirdAuthCore

// MARK: - Test context

/// Context for CSRF middleware tests. Carries the CSRFProtectedContext
/// refinement so `CSRFMiddleware` and `SkipCSRF` compile.
struct CSRFTestContext: CSRFProtectedContext {
    typealias User = TestUser

    var coreContext: CoreRequestContextStorage
    var user: TestUser?
    var flashMessages: [FlashMessage] = []
    var masqueradingAs: String?
    var realUserID: UUID?
    var csrfToken: String?
    var csrfValidated: Bool = false
    var csrfSkipped: Bool = false

    init(source: ApplicationRequestContextSource) {
        self.coreContext = .init(source: source)
    }
}

// MARK: - Test harness

struct CSRFTestFixture {
    let fluent: Fluent
    let user: TestUser
    let sessionToken: String
    let csrfToken: String
}

/// Build an app with CSRFMiddleware wrapped around a POST /echo route
/// that echoes the body it received. Also registers a GET /ping route
/// to test that safe methods skip.
///
/// When `includeSkipGroup` is true, a second POST /webhook route is
/// installed under a `SkipCSRF` outer group (applied *before*
/// `CSRFMiddleware`) to exercise the opt-out path.
private func withCSRFApp(
    includeSkipGroup: Bool = false,
    testBody: @Sendable (any TestClientProtocol, CSRFTestFixture) async throws -> Void
) async throws {
    var logger = Logger(label: "hb-auth-csrf-tests")
    logger.logLevel = .warning

    let fluent = Fluent(logger: logger)
    fluent.databases.use(.sqlite(.memory), as: .sqlite)
    await fluent.migrations.add(CreateTestUsers())
    await addAuthMigrations(to: fluent, userTable: TestUser.schema)
    try await fluent.migrate()

    let db = fluent.db()
    let user = TestUser(email: "u@example.com", displayName: "User", isAdmin: false)
    try await user.save(on: db)

    let sessionToken = UUID().uuidString
    let session = AuthSession(
        userID: try user.requireID(),
        token: sessionToken,
        expiresAt: Date().addingTimeInterval(3600)
    )
    try await session.save(on: db)

    let fixture = CSRFTestFixture(
        fluent: fluent, user: user,
        sessionToken: sessionToken, csrfToken: session.csrfToken
    )

    let router = Router(context: CSRFTestContext.self)
    router.add(middleware: SessionMiddleware<CSRFTestContext>(db: db))

    if includeSkipGroup {
        // Outer SkipCSRF group; its own CSRFMiddleware sits inside,
        // so SkipCSRF's flag is visible when CSRFMiddleware checks it.
        let skipGroup = router.group("")
            .add(middleware: SkipCSRF<CSRFTestContext>())
            .add(middleware: CSRFMiddleware<CSRFTestContext>())
        skipGroup.post("/webhook") { request, context -> Response in
            #expect(context.csrfValidated)
            return Response(
                status: .ok, headers: [:],
                body: .init(byteBuffer: ByteBuffer(string: "WEBHOOK_OK"))
            )
        }
    }

    let protected = router.group("").add(middleware: CSRFMiddleware<CSRFTestContext>())
    protected.get("/ping") { _, context -> Response in
        #expect(context.csrfValidated)
        return Response(
            status: .ok, headers: [:],
            body: .init(byteBuffer: ByteBuffer(string: "PONG"))
        )
    }
    protected.post("/echo") { request, context -> Response in
        #expect(context.csrfValidated)
        var req = request
        let collected = try await req.collectBody(upTo: 1024 * 1024)
        return Response(
            status: .ok,
            headers: [.contentType: request.headers[.contentType] ?? "application/octet-stream"],
            body: .init(byteBuffer: collected)
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

// MARK: - Tests

@Suite("CSRFMiddleware")
struct CSRFMiddlewareTests {

    @Test("GET requests skip CSRF even when authenticated")
    func safeMethodSkips() async throws {
        try await withCSRFApp { client, fx in
            try await client.execute(
                uri: "/ping",
                method: .get,
                headers: [
                    .cookie: "\(SessionConfiguration.cookieName)=\(fx.sessionToken)"
                ]
            ) { response in
                #expect(response.status == .ok)
                #expect(String(buffer: response.body) == "PONG")
            }
        }
    }

    @Test("Unauthenticated POST (no session cookie) skips CSRF")
    func unauthenticatedSkips() async throws {
        try await withCSRFApp { client, _ in
            try await client.execute(
                uri: "/echo",
                method: .post,
                headers: [.contentType: "application/x-www-form-urlencoded"],
                body: ByteBuffer(string: "hello=world")
            ) { response in
                #expect(response.status == .ok)
                #expect(String(buffer: response.body) == "hello=world")
            }
        }
    }

    @Test("Bearer-authenticated POST skips CSRF (no cookie; bearer token present)")
    func bearerSkips() async throws {
        try await withCSRFApp { client, _ in
            try await client.execute(
                uri: "/echo",
                method: .post,
                headers: [
                    .authorization: "Bearer abc.def.ghi",
                    .contentType: "application/json",
                ],
                body: ByteBuffer(string: "{\"hi\":1}")
            ) { response in
                // No session cookie → the unauth-skip path fires. Even
                // if a cookie were present, the bearer-skip path would
                // fire — we exercise that in the next test.
                #expect(response.status == .ok)
            }
        }
    }

    @Test("Session-authenticated POST with bearer header still skips CSRF")
    func bearerWithCookieSkips() async throws {
        try await withCSRFApp { client, fx in
            try await client.execute(
                uri: "/echo",
                method: .post,
                headers: [
                    .cookie: "\(SessionConfiguration.cookieName)=\(fx.sessionToken)",
                    .authorization: "Bearer some.access.token",
                    .contentType: "application/json",
                ],
                body: ByteBuffer(string: "{}")
            ) { response in
                #expect(response.status == .ok)
            }
        }
    }

    @Test("POST with valid CSRF token in form body succeeds and body is re-readable")
    func formBodyValidToken() async throws {
        try await withCSRFApp { client, fx in
            let body = "csrf_token=\(fx.csrfToken)&foo=bar"
            try await client.execute(
                uri: "/echo",
                method: .post,
                headers: [
                    .cookie: "\(SessionConfiguration.cookieName)=\(fx.sessionToken)",
                    .contentType: "application/x-www-form-urlencoded",
                ],
                body: ByteBuffer(string: body)
            ) { response in
                #expect(response.status == .ok)
                // Handler re-collected the body, so the echoed payload
                // proves the re-attach works.
                #expect(String(buffer: response.body) == body)
            }
        }
    }

    @Test("POST with mismatched form-body token is rejected with 403")
    func formBodyMismatch() async throws {
        try await withCSRFApp { client, fx in
            let body = "csrf_token=not-the-real-token&foo=bar"
            try await client.execute(
                uri: "/echo",
                method: .post,
                headers: [
                    .cookie: "\(SessionConfiguration.cookieName)=\(fx.sessionToken)",
                    .contentType: "application/x-www-form-urlencoded",
                ],
                body: ByteBuffer(string: body)
            ) { response in
                #expect(response.status == .forbidden)
            }
        }
    }

    @Test("POST with missing form-body token is rejected with 403")
    func formBodyMissing() async throws {
        try await withCSRFApp { client, fx in
            let body = "foo=bar"
            try await client.execute(
                uri: "/echo",
                method: .post,
                headers: [
                    .cookie: "\(SessionConfiguration.cookieName)=\(fx.sessionToken)",
                    .contentType: "application/x-www-form-urlencoded",
                ],
                body: ByteBuffer(string: body)
            ) { response in
                #expect(response.status == .forbidden)
            }
        }
    }

    @Test("JSON POST with valid X-CSRF-Token header succeeds")
    func jsonHeaderValid() async throws {
        try await withCSRFApp { client, fx in
            try await client.execute(
                uri: "/echo",
                method: .post,
                headers: [
                    .cookie: "\(SessionConfiguration.cookieName)=\(fx.sessionToken)",
                    .contentType: "application/json",
                    .csrfToken: fx.csrfToken,
                ],
                body: ByteBuffer(string: "{\"foo\":1}")
            ) { response in
                #expect(response.status == .ok)
                #expect(String(buffer: response.body) == "{\"foo\":1}")
            }
        }
    }

    @Test("JSON POST without X-CSRF-Token header is rejected with 403")
    func jsonHeaderMissing() async throws {
        try await withCSRFApp { client, fx in
            try await client.execute(
                uri: "/echo",
                method: .post,
                headers: [
                    .cookie: "\(SessionConfiguration.cookieName)=\(fx.sessionToken)",
                    .contentType: "application/json",
                ],
                body: ByteBuffer(string: "{\"foo\":1}")
            ) { response in
                #expect(response.status == .forbidden)
            }
        }
    }

    @Test("JSON POST with wrong X-CSRF-Token header is rejected with 403")
    func jsonHeaderMismatch() async throws {
        try await withCSRFApp { client, fx in
            try await client.execute(
                uri: "/echo",
                method: .post,
                headers: [
                    .cookie: "\(SessionConfiguration.cookieName)=\(fx.sessionToken)",
                    .contentType: "application/json",
                    .csrfToken: "wrong-token",
                ],
                body: ByteBuffer(string: "{\"foo\":1}")
            ) { response in
                #expect(response.status == .forbidden)
            }
        }
    }

    @Test("Multipart POST with X-CSRF-Token header succeeds")
    func multipartHeaderValid() async throws {
        try await withCSRFApp { client, fx in
            try await client.execute(
                uri: "/echo",
                method: .post,
                headers: [
                    .cookie: "\(SessionConfiguration.cookieName)=\(fx.sessionToken)",
                    .contentType: "multipart/form-data; boundary=X",
                    .csrfToken: fx.csrfToken,
                ],
                body: ByteBuffer(string: "--X\r\nContent-Disposition: form-data; name=\"f\"\r\n\r\nv\r\n--X--\r\n")
            ) { response in
                #expect(response.status == .ok)
            }
        }
    }

    @Test("Multipart POST without X-CSRF-Token header is rejected (body path not used)")
    func multipartHeaderMissing() async throws {
        try await withCSRFApp { client, fx in
            try await client.execute(
                uri: "/echo",
                method: .post,
                headers: [
                    .cookie: "\(SessionConfiguration.cookieName)=\(fx.sessionToken)",
                    .contentType: "multipart/form-data; boundary=X",
                ],
                body: ByteBuffer(string: "--X\r\nContent-Disposition: form-data; name=\"csrf_token\"\r\n\r\n\(fx.csrfToken)\r\n--X--\r\n")
            ) { response in
                // Multipart body is intentionally not parsed — header
                // is required. Expect 403 even though the field is
                // technically present in the body.
                #expect(response.status == .forbidden)
            }
        }
    }

    @Test("SkipCSRF group bypasses CSRF validation")
    func skipOptOut() async throws {
        try await withCSRFApp(includeSkipGroup: true) { client, fx in
            try await client.execute(
                uri: "/webhook",
                method: .post,
                headers: [
                    .cookie: "\(SessionConfiguration.cookieName)=\(fx.sessionToken)",
                    .contentType: "application/json",
                    // Deliberately NO csrf token.
                ],
                body: ByteBuffer(string: "{\"event\":\"test\"}")
            ) { response in
                #expect(response.status == .ok)
                #expect(String(buffer: response.body) == "WEBHOOK_OK")
            }
        }
    }

    @Test("Header token is preferred when both header and body supply a token")
    func headerTakesPriorityOverBody() async throws {
        try await withCSRFApp { client, fx in
            // Header correct, body has a different (wrong) value. Middleware
            // checks the header first and accepts. Body is not consumed
            // (content-type is JSON, not form).
            try await client.execute(
                uri: "/echo",
                method: .post,
                headers: [
                    .cookie: "\(SessionConfiguration.cookieName)=\(fx.sessionToken)",
                    .contentType: "application/json",
                    .csrfToken: fx.csrfToken,
                ],
                body: ByteBuffer(string: "{\"csrf_token\":\"wrong\"}")
            ) { response in
                #expect(response.status == .ok)
            }
        }
    }
}
