import FluentKit
import Foundation
import Hummingbird
import HummingbirdAuth
import HummingbirdAuthCore
import Logging
import NIOCore

/// Install OAuth 2.1 routes on a router.
///
/// Registers:
/// - `GET /.well-known/oauth-authorization-server` (RFC 8414)
/// - `POST /oauth/register` (RFC 7591 dynamic client registration)
/// - `POST /oauth/token` (authorization code + refresh token grants)
///
/// The authorization endpoint (GET/POST /oauth/authorize) is NOT registered
/// here because its consent UI is app-specific. Apps should implement their
/// own consent page using `OAuthService.createAuthorizationCode()`.
/// - Parameter requireAuthForRegistration: When `true` (the default), the
///   `/oauth/register` endpoint requires an authenticated session (admin).
///   Set to `false` only for fully open registration use cases.
public func installOAuthRoutes<Context: OAuthRequestContextProtocol>(
    on router: Router<Context>,
    oauthService: OAuthService,
    logger: Logger,
    pathPrefix: String = "/oauth",
    requireAuthForRegistration: Bool = true
) where Context.User: FluentAuthUser {
    let config = oauthService.config

    // Well-known metadata
    router.get(".well-known/oauth-authorization-server") { _, _ -> Response in
        let metadata: [String: Any] = [
            "issuer": config.baseURL,
            "authorization_endpoint": "\(config.baseURL)\(pathPrefix)/authorize",
            "token_endpoint": "\(config.baseURL)\(pathPrefix)/token",
            "registration_endpoint": "\(config.baseURL)\(pathPrefix)/register",
            "scopes_supported": Array(config.validScopes.sorted()),
            "response_types_supported": ["code"],
            "grant_types_supported": ["authorization_code", "refresh_token"],
            "code_challenge_methods_supported": ["S256"],
            "token_endpoint_auth_methods_supported": ["none"],
        ]
        let data = try JSONSerialization.data(withJSONObject: metadata)
        return Response(
            status: .ok,
            headers: [.contentType: "application/json"],
            body: .init(byteBuffer: ByteBuffer(data: data))
        )
    }

    let oauth = router.group(RouterPath(pathPrefix))

    // Dynamic client registration (RFC 7591)
    // When requireAuthForRegistration is true, only admins can register clients.
    if requireAuthForRegistration {
        let adminOAuth = oauth.group(context: AdminContext<Context>.self)
        adminOAuth.post("register") { request, context -> Response in
            try await handleClientRegistration(request: request, oauthService: oauthService)
        }
    } else {
        oauth.post("register") { request, context -> Response in
            try await handleClientRegistration(request: request, oauthService: oauthService)
        }
    }

    // Token endpoint
    oauth.post("token") { request, context -> Response in
        let bodyBuffer = try await request.body.collect(upTo: 1024 * 1024)

        // Accept both form-encoded and JSON
        let body: TokenRequest
        let contentType = request.headers[.contentType] ?? ""
        if contentType.contains("application/json") {
            body = try JSONDecoder().decode(TokenRequest.self, from: bodyBuffer)
        } else {
            // Parse URL-encoded form body
            let formString = String(buffer: bodyBuffer)
            body = parseTokenRequest(from: formString)
        }

        do {
            let token: OAuthToken
            switch body.grant_type {
            case "authorization_code":
                guard let code = body.code,
                      let clientID = body.client_id,
                      let redirectURI = body.redirect_uri,
                      let codeVerifier = body.code_verifier else {
                    throw OAuthError.invalidRequest("Missing required parameters")
                }
                token = try await oauthService.exchangeCodeForToken(
                    code: code, clientID: clientID,
                    redirectURI: redirectURI, codeVerifier: codeVerifier
                )

            case "refresh_token":
                guard let refreshToken = body.refresh_token,
                      let clientID = body.client_id else {
                    throw OAuthError.invalidRequest("Missing required parameters")
                }
                token = try await oauthService.refreshAccessToken(
                    refreshToken: refreshToken, clientID: clientID
                )

            default:
                throw OAuthError.unsupportedGrantType
            }

            let response = TokenResponse(
                access_token: token.accessToken,
                token_type: "Bearer",
                expires_in: Int(oauthService.config.accessTokenTTL),
                refresh_token: token.refreshToken,
                scope: token.scope
            )
            let data = try JSONEncoder().encode(response)
            return Response(
                status: .ok,
                headers: [.contentType: "application/json"],
                body: .init(byteBuffer: ByteBuffer(data: data))
            )
        } catch let error as OAuthError {
            let status: HTTPResponse.Status = error.errorCode == "invalid_client" ? .unauthorized : .badRequest
            let errorResponse = OAuthErrorResponse(
                error: error.errorCode,
                error_description: error.errorDescription
            )
            let data = try JSONEncoder().encode(errorResponse)
            return Response(
                status: status,
                headers: [.contentType: "application/json"],
                body: .init(byteBuffer: ByteBuffer(data: data))
            )
        }
    }
}

// MARK: - Request/Response Types

struct ClientRegistrationRequest: Codable {
    let client_name: String
    let redirect_uris: [String]
    let grant_types: [String]?
    let scope: String?
}

struct ClientRegistrationResponse: Codable {
    let client_id: String
    let client_name: String
    let redirect_uris: [String]
    let grant_types: [String]
    let scope: String
    let token_endpoint_auth_method: String
}

struct TokenRequest: Codable {
    let grant_type: String
    let code: String?
    let client_id: String?
    let redirect_uri: String?
    let code_verifier: String?
    let refresh_token: String?
}

struct TokenResponse: Codable {
    let access_token: String
    let token_type: String
    let expires_in: Int
    let refresh_token: String
    let scope: String
}

struct OAuthErrorResponse: Codable {
    let error: String
    let error_description: String
}

private func handleClientRegistration(
    request: Request,
    oauthService: OAuthService
) async throws -> Response {
    let bodyBuffer = try await request.body.collect(upTo: 1024 * 1024)
    let body = try JSONDecoder().decode(ClientRegistrationRequest.self, from: bodyBuffer)

    guard !body.client_name.trimmingCharacters(in: .whitespaces).isEmpty else {
        throw HTTPError(.badRequest, message: "client_name is required")
    }
    guard !body.redirect_uris.isEmpty else {
        throw HTTPError(.badRequest, message: "redirect_uris is required")
    }

    let client = try await oauthService.registerClient(
        name: body.client_name,
        redirectURIs: body.redirect_uris,
        grantTypes: body.grant_types,
        scope: body.scope
    )

    let response = ClientRegistrationResponse(
        client_id: client.clientID,
        client_name: client.clientName,
        redirect_uris: client.redirectURIList,
        grant_types: client.grantTypeList,
        scope: client.scope,
        token_endpoint_auth_method: "none"
    )
    let data = try JSONEncoder().encode(response)
    return Response(
        status: .created,
        headers: [.contentType: "application/json"],
        body: .init(byteBuffer: ByteBuffer(data: data))
    )
}

/// Parse a URL-encoded form body into a TokenRequest.
private func parseTokenRequest(from formString: String) -> TokenRequest {
    var params: [String: String] = [:]
    for pair in formString.split(separator: "&") {
        let parts = pair.split(separator: "=", maxSplits: 1)
        if parts.count == 2 {
            let key = String(parts[0]).removingPercentEncoding ?? String(parts[0])
            let value = String(parts[1]).removingPercentEncoding ?? String(parts[1])
            params[key] = value
        }
    }
    return TokenRequest(
        grant_type: params["grant_type"] ?? "",
        code: params["code"],
        client_id: params["client_id"],
        redirect_uri: params["redirect_uri"],
        code_verifier: params["code_verifier"],
        refresh_token: params["refresh_token"]
    )
}
