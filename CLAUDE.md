# hummingbird-auth

Layered passkey authentication library for Hummingbird 2 web apps.

## Architecture

Four Swift package targets with a clear dependency hierarchy:

```
HummingbirdAuthCore       ← protocols, config, view models (no Fluent)
    |         \
HummingbirdAuth            HummingbirdAuthViews
(Fluent models,            (Plot components for
 services, middleware,      login, registration,
 route installers)          profile, admin UI)
    |
HummingbirdAuthOAuth
(OAuth 2.1 server)
```

Core has no Fluent dependency — it defines protocols and data types. Auth depends on Core + Fluent + WebAuthn. Views depends on Core + Plot (not Auth). OAuth depends on Auth.

## Key Design Decisions

### Generic User Protocol
The library does NOT own the User model. Apps provide their own Fluent model conforming to `FluentAuthUser` (which extends `AuthUser` + `Model`). Library models store user references as plain `UUID` fields (not `@Parent` generics) to avoid making every model type generic. Migrations accept a `userTable: String` parameter for FK constraints.

### Route Installers with Render Callbacks
`installProfileRoutes()` and `installAdminRoutes()` accept closures returning `ResponseGenerator` so apps can wrap library view components in their own page layout without the library depending on Plot. The closures receive view model structs from Core.

### Cookie Path Scoping
The session cookie name is fixed as `hb-auth` (see `SessionConfiguration.cookieName`). Cookie path is configurable for multi-app domains with path-based ingress routing.

### Masquerade
`SessionMiddleware` populates `context.masqueradingAs` and `context.realUserID` from the session's masquerade fields. `AdminContext` allows access when `realUserID != nil` (the real user started as admin). `AuthenticatedContext` passes masquerade state through from the parent context.

### Base64URL Normalization
WebAuthn libraries inconsistently use standard base64 and base64url. All credential IDs and challenges are normalized to base64url via `normalizeToBase64URL()` in `Utilities.swift` before storage. See the `feedback_base64_normalization` memory for context.

## File Layout

```
Sources/
  HummingbirdAuthCore/
    AuthUser.swift              # AuthUser protocol
    AuthRequestContext.swift    # Context protocol + AuthenticatedContext + AdminContext
    AuthConfiguration.swift     # All config types (Passkey, Session, Invitation, Callbacks)
    FlashMessage.swift          # Session-persisted notification messages
    ViewModels.swift            # ProfileViewModel, AdminUserViewModel, AdminInvitationViewModel
    Utilities.swift             # generateSecureToken(), base64url encode/decode

  HummingbirdAuth/
    FluentAuthUser.swift        # FluentAuthUser protocol bridging AuthUser + Model
    Models/                     # AuthSession, PasskeyCredential, PasskeyChallenge, Invitation
    Services/                   # PasskeyService, InvitationService
    Middleware/                 # SessionMiddleware, AuthRedirectMiddleware
    Migrations/                 # AuthMigrations.swift (all table creation)
    Routes/                     # installAuthRoutes, installProfileRoutes, installAdminRoutes

  HummingbirdAuthViews/
    LoginView.swift             # Embeddable passkey login form
    RegistrationView.swift      # Embeddable registration form
    ProfileView.swift           # Editable profile form
    AdminUsersView.swift        # User table with role/masquerade controls
    AdminInvitationsView.swift  # Invitation table with create/copy/delete
    StandalonePages.swift       # Convenience full-page wrappers
    WebAuthnScript.swift        # JS for passkey ceremonies (~250 lines)

  HummingbirdAuthOAuth/
    Models/                     # OAuthClient, OAuthAuthorizationCode, OAuthToken
    Services/OAuthService.swift # Auth code, token exchange, PKCE, cleanup
    Middleware/                 # OAuthBearerMiddleware
    Migrations/                 # OAuth table creation
    Routes/                     # installOAuthRoutes (well-known, register, token)
```

## Security

See `SECURITY_AUDIT.md` for findings from the 2026-04-16 security review. Critical items should be addressed before production deployment.

## Testing

Tests use in-memory SQLite via FluentSQLiteDriver. Run with `swift test`.

## Conventions

- All models use `@unchecked Sendable` (Fluent requirement)
- Public API types are in Core; Fluent-specific types in Auth
- Route installers are free functions, not methods on a type
- View components are Plot `Component` structs in the Views target
- The WebAuthn JS auto-wires to element IDs (`auth-login-button`, `auth-registration-form`) and reads `data-auth-prefix` for API path discovery

## Related Projects

- [Prospero](https://github.com/samalone/prospero) — First consumer of this library
- [plot-htmx](https://github.com/samalone/plot-htmx) — Plot extensions for HTMX/SSE
- Life Balance — The app this library was extracted from
