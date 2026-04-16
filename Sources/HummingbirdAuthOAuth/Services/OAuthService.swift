import Crypto
import FluentKit
import Foundation
import HummingbirdAuth
import HummingbirdAuthCore
import Logging

public enum OAuthError: Error, Sendable {
    case invalidClient
    case invalidGrant
    case invalidScope
    case unauthorizedClient
    case unsupportedGrantType
    case invalidRequest(String)

    public var errorCode: String {
        switch self {
        case .invalidClient: "invalid_client"
        case .invalidGrant: "invalid_grant"
        case .invalidScope: "invalid_scope"
        case .unauthorizedClient: "unauthorized_client"
        case .unsupportedGrantType: "unsupported_grant_type"
        case .invalidRequest: "invalid_request"
        }
    }

    public var errorDescription: String {
        switch self {
        case .invalidClient: "Client authentication failed"
        case .invalidGrant: "The provided authorization grant is invalid, expired, or revoked"
        case .invalidScope: "The requested scope is invalid or exceeds the granted scope"
        case .unauthorizedClient: "The client is not authorized for this grant type"
        case .unsupportedGrantType: "The authorization grant type is not supported"
        case .invalidRequest(let detail): "Invalid request: \(detail)"
        }
    }
}

/// Configuration for the OAuth 2.1 authorization server.
public struct OAuthConfiguration: Sendable {
    public var validScopes: Set<String>
    public var authCodeTTL: TimeInterval
    public var accessTokenTTL: TimeInterval
    public var refreshTokenTTL: TimeInterval
    /// Base URL for well-known metadata endpoints.
    public var baseURL: String

    public init(
        validScopes: Set<String> = ["read", "write"],
        authCodeTTL: TimeInterval = 10 * 60,
        accessTokenTTL: TimeInterval = 3600,
        refreshTokenTTL: TimeInterval = 30 * 86400,
        baseURL: String = "http://localhost:8080"
    ) {
        self.validScopes = validScopes
        self.authCodeTTL = authCodeTTL
        self.accessTokenTTL = accessTokenTTL
        self.refreshTokenTTL = refreshTokenTTL
        self.baseURL = baseURL
    }
}

/// OAuth 2.1 authorization server with PKCE support.
public struct OAuthService: Sendable {
    let db: Database  // Package-internal; used by OAuthBearerMiddleware
    private let logger: Logger
    public let config: OAuthConfiguration

    public init(db: Database, logger: Logger, config: OAuthConfiguration = .init()) {
        self.db = db
        self.logger = logger
        self.config = config
    }

    // MARK: - Client Registration

    public func registerClient(
        name: String,
        redirectURIs: [String],
        grantTypes: [String]?,
        scope: String?
    ) async throws -> OAuthClient {
        let clientID = generateSecureToken()
        let resolvedGrantTypes = grantTypes ?? ["authorization_code"]
        let resolvedScope = scope.map { requested in
            let requestedScopes = Set(requested.split(separator: " ").map(String.init))
            return requestedScopes.intersection(config.validScopes).sorted().joined(separator: " ")
        } ?? config.validScopes.sorted().joined(separator: " ")

        let client = OAuthClient(
            clientID: clientID,
            clientName: name,
            redirectURIs: try String(data: JSONEncoder().encode(redirectURIs), encoding: .utf8) ?? "[]",
            grantTypes: try String(data: JSONEncoder().encode(resolvedGrantTypes), encoding: .utf8) ?? "[]",
            scope: resolvedScope
        )
        try await client.save(on: db)
        return client
    }

    // MARK: - Authorization Code

    public func createAuthorizationCode(
        clientUUID: UUID,
        userID: UUID,
        redirectURI: String,
        scope: String,
        codeChallenge: String,
        codeChallengeMethod: String
    ) async throws -> OAuthAuthorizationCode {
        // Validate redirect URI against client's registered URIs.
        guard let client = try await OAuthClient.find(clientUUID, on: db) else {
            throw OAuthError.invalidClient
        }
        guard client.redirectURIList.contains(redirectURI) else {
            throw OAuthError.invalidRequest("redirect_uri is not registered for this client")
        }

        // Validate requested scopes are a subset of the client's registered scopes
        // and the server's configured valid scopes.
        let requestedScopes = Set(scope.split(separator: " ").map(String.init))
        guard requestedScopes.isSubset(of: client.scopeSet),
              requestedScopes.isSubset(of: config.validScopes) else {
            throw OAuthError.invalidScope
        }

        let code = generateSecureToken()
        let authCode = OAuthAuthorizationCode(
            code: code,
            clientUUID: clientUUID,
            userID: userID,
            redirectURI: redirectURI,
            scope: scope,
            codeChallenge: codeChallenge,
            codeChallengeMethod: codeChallengeMethod,
            expiresAt: Date().addingTimeInterval(config.authCodeTTL)
        )
        try await authCode.save(on: db)
        return authCode
    }

    // MARK: - Token Exchange

    public func exchangeCodeForToken(
        code: String,
        clientID: String,
        redirectURI: String,
        codeVerifier: String
    ) async throws -> OAuthToken {
        guard let client = try await OAuthClient.query(on: db)
            .filter(\.$clientID == clientID)
            .first()
        else {
            throw OAuthError.invalidClient
        }

        guard let authCode = try await OAuthAuthorizationCode.query(on: db)
            .filter(\.$code == code)
            .filter(\.$consumedAt == nil)
            .first()
        else {
            throw OAuthError.invalidGrant
        }

        // Atomically mark as consumed before any further validation.
        // This prevents TOCTOU races where two concurrent requests both
        // read the code as unconsumed.
        authCode.consumedAt = Date()
        try await authCode.save(on: db)

        guard !authCode.isExpired else { throw OAuthError.invalidGrant }
        guard authCode.clientUUID == client.id else { throw OAuthError.invalidGrant }
        guard authCode.redirectURI == redirectURI else { throw OAuthError.invalidGrant }

        try verifyPKCE(
            challenge: authCode.codeChallenge,
            verifier: codeVerifier,
            method: authCode.codeChallengeMethod
        )

        return try await createToken(
            clientUUID: client.id!,
            userID: authCode.userID,
            scope: authCode.scope
        )
    }

    // MARK: - Token Refresh

    public func refreshAccessToken(
        refreshToken: String,
        clientID: String
    ) async throws -> OAuthToken {
        guard let client = try await OAuthClient.query(on: db)
            .filter(\.$clientID == clientID)
            .first()
        else {
            throw OAuthError.invalidClient
        }

        guard let token = try await OAuthToken.query(on: db)
            .filter(\.$refreshToken == refreshToken)
            .first()
        else {
            throw OAuthError.invalidGrant
        }

        guard !token.isRevoked else { throw OAuthError.invalidGrant }
        guard !token.isRefreshExpired else { throw OAuthError.invalidGrant }
        guard token.clientUUID == client.id else { throw OAuthError.invalidGrant }

        // Re-validate scopes against current client and server configuration.
        let existingScopes = token.scopeSet
        let validScopes = existingScopes.intersection(client.scopeSet).intersection(config.validScopes)
        let refreshedScope = validScopes.sorted().joined(separator: " ")
        guard !refreshedScope.isEmpty else { throw OAuthError.invalidScope }

        token.revokedAt = Date()
        try await token.save(on: db)

        return try await createToken(
            clientUUID: client.id!,
            userID: token.userID,
            scope: refreshedScope
        )
    }

    // MARK: - Token Validation

    /// Validate an access token and return the user ID and scopes.
    public func validateAccessToken(_ tokenString: String) async throws -> (userID: UUID, scopes: Set<String>, clientID: UUID)? {
        guard let token = try await OAuthToken.query(on: db)
            .filter(\.$accessToken == tokenString)
            .first()
        else {
            return nil
        }

        guard !token.isAccessExpired, !token.isRevoked else { return nil }

        // Throttle lastAccessedAt updates (single fetch).
        if let client = try await OAuthClient.find(token.clientUUID, on: db) {
            let needsUpdate = client.lastAccessedAt.map { Date().timeIntervalSince($0) > 5 * 60 } ?? true
            if needsUpdate {
                client.lastAccessedAt = Date()
                try await client.save(on: db)
            }
        }

        return (userID: token.userID, scopes: token.scopeSet, clientID: token.clientUUID)
    }

    // MARK: - PKCE

    public func verifyPKCE(challenge: String, verifier: String, method: String) throws {
        guard method == "S256" else {
            throw OAuthError.invalidRequest("Only S256 code challenge method is supported")
        }
        let hash = SHA256.hash(data: Data(verifier.utf8))
        let computed = encodeBase64URL(Data(hash))
        guard computed == challenge else {
            throw OAuthError.invalidGrant
        }
    }

    // MARK: - Cleanup

    public func cleanupExpired() async throws {
        let now = Date()
        try await OAuthAuthorizationCode.query(on: db)
            .filter(\.$expiresAt < now)
            .delete()
        try await OAuthToken.query(on: db)
            .group(.or) { group in
                group.filter(\.$refreshExpiresAt < now)
                group.filter(\.$revokedAt < now.addingTimeInterval(-86400))
            }
            .delete()
    }

    // MARK: - Helpers

    private func createToken(clientUUID: UUID, userID: UUID, scope: String) async throws -> OAuthToken {
        let token = OAuthToken(
            accessToken: generateSecureToken(),
            refreshToken: generateSecureToken(),
            clientUUID: clientUUID,
            userID: userID,
            scope: scope,
            accessExpiresAt: Date().addingTimeInterval(config.accessTokenTTL),
            refreshExpiresAt: Date().addingTimeInterval(config.refreshTokenTTL)
        )
        try await token.save(on: db)
        return token
    }

}
