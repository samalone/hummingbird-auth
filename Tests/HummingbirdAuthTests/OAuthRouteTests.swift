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
@testable import HummingbirdAuthOAuth

// MARK: - Test context

struct OAuthTestContext: OAuthRequestContextProtocol {
    typealias User = TestUser

    var coreContext: CoreRequestContextStorage
    var user: TestUser?
    var flashMessages: [FlashMessage] = []
    var masqueradingAs: String?
    var realUserID: UUID?
    var csrfToken: String?
    var csrfSkipped: Bool = false
    var oauthScopes: Set<String> = []
    var oauthClientID: UUID?

    init(source: ApplicationRequestContextSource) {
        self.coreContext = .init(source: source)
    }
}

// MARK: - Test harness

/// Build an app with the OAuth routes installed and open registration, so the
/// tests exercise request parsing without session/admin plumbing.
private func withOAuthApp(
    testBody: @Sendable (any TestClientProtocol) async throws -> Void
) async throws {
    var logger = Logger(label: "hb-auth-oauth-tests")
    logger.logLevel = .warning

    let fluent = Fluent(logger: logger)
    fluent.databases.use(.sqlite(.memory), as: .sqlite)
    await fluent.migrations.add(CreateTestUsers())
    await addAuthMigrations(to: fluent, userTable: TestUser.schema)
    await addOAuthMigrations(to: fluent, userTable: TestUser.schema)
    try await fluent.migrate()

    let oauthService = OAuthService(db: fluent.db(), logger: logger)
    let router = Router(context: OAuthTestContext.self)
    installOAuthRoutes(
        on: router, oauthService: oauthService, logger: logger,
        requireAuthForRegistration: false
    )

    var app = Application(
        router: router,
        configuration: .init(address: .hostname("127.0.0.1", port: 0)),
        logger: logger
    )
    app.addServices(fluent)

    do {
        try await app.test(.router) { client in
            try await testBody(client)
        }
    } catch {
        try? await fluent.shutdown()
        throw error
    }
    try await fluent.shutdown()
}

private func post(
    _ client: any TestClientProtocol,
    _ uri: String,
    contentType: String = "application/json",
    body: String,
    check: @escaping (TestResponse) async throws -> Void
) async throws {
    try await client.execute(
        uri: uri,
        method: .post,
        headers: [.contentType: contentType],
        body: ByteBuffer(string: body)
    ) { response in
        try await check(response)
    }
}

/// Assert a 400 response carrying the RFC 6749 / RFC 7591 JSON error object.
private func expectOAuthError(_ response: TestResponse, _ code: String) throws {
    #expect(response.status == .badRequest)
    #expect(response.headers[.contentType]?.contains("application/json") == true)
    let error = try JSONDecoder().decode(OAuthErrorResponse.self, from: Data(buffer: response.body))
    #expect(error.error == code)
    #expect(!error.error_description.isEmpty)
}

// MARK: - Tests

@Suite("OAuth routes")
struct OAuthRouteTests {

    @Test("Valid registration returns 201 with a client_id")
    func validRegistration() async throws {
        try await withOAuthApp { client in
            try await post(
                client, "/oauth/register",
                body: #"{"client_name": "App", "redirect_uris": ["https://example.com/cb"]}"#
            ) { response in
                #expect(response.status == .created)
                #expect(response.headers[.contentType]?.contains("application/json") == true)
                let body = try JSONDecoder().decode(ClientRegistrationResponse.self, from: Data(buffer: response.body))
                #expect(!body.client_id.isEmpty)
                #expect(body.redirect_uris == ["https://example.com/cb"])
            }
        }
    }

    @Test(
        "Malformed registration bodies return 400 invalid_client_metadata",
        arguments: [
            "",
            "{}",
            "not json",
            #"{"client_name": 1, "redirect_uris": ["https://example.com/cb"]}"#,
            #"{"client_name": "  ", "redirect_uris": ["https://example.com/cb"]}"#,
        ]
    )
    func malformedRegistration(body: String) async throws {
        try await withOAuthApp { client in
            try await post(client, "/oauth/register", body: body) { response in
                try expectOAuthError(response, "invalid_client_metadata")
            }
        }
    }

    @Test(
        "Missing or invalid redirect_uris return 400 invalid_redirect_uri",
        arguments: [
            #"{"client_name": "x", "redirect_uris": []}"#,
            #"{"client_name": "x", "redirect_uris": ["http://evil.example.com/cb"]}"#,
            #"{"client_name": "x", "redirect_uris": ["https://example.com/cb#frag"]}"#,
        ]
    )
    func invalidRedirectURIs(body: String) async throws {
        try await withOAuthApp { client in
            try await post(client, "/oauth/register", body: body) { response in
                try expectOAuthError(response, "invalid_redirect_uri")
            }
        }
    }

    @Test("Token endpoint with malformed JSON returns 400 invalid_request")
    func tokenMalformedJSON() async throws {
        try await withOAuthApp { client in
            try await post(client, "/oauth/token", body: "{") { response in
                try expectOAuthError(response, "invalid_request")
            }
        }
    }

    @Test("Token endpoint with an unsupported grant type returns 400 unsupported_grant_type")
    func tokenUnsupportedGrant() async throws {
        try await withOAuthApp { client in
            try await post(
                client, "/oauth/token",
                contentType: "application/x-www-form-urlencoded",
                body: "grant_type=password"
            ) { response in
                try expectOAuthError(response, "unsupported_grant_type")
            }
        }
    }
}
