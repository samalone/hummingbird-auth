# hummingbird-auth

Layered passkey authentication library for [Hummingbird 2](https://github.com/hummingbird-project/hummingbird) web apps. Provides passkey (WebAuthn) login, server-side sessions, invitation-based registration, admin user management, masquerade, and an optional OAuth 2.1 authorization server.

## Targets

Import only what you need:

| Target | Purpose | Dependencies |
|--------|---------|-------------|
| **HummingbirdAuthCore** | Protocols, configuration, view models | Hummingbird |
| **HummingbirdAuth** | Fluent models, services, middleware, route installers | Core + Fluent + WebAuthn |
| **HummingbirdAuthViews** | Plot HTML components (login, registration, profile, admin) | Core + Plot + PlotHTMX |
| **HummingbirdAuthOAuth** | OAuth 2.1 server with PKCE | Auth + Fluent |

Most apps import `HummingbirdAuth` and `HummingbirdAuthViews`.

## Quick Start

### 1. Define your User model

```swift
import FluentKit
import HummingbirdAuth

final class AppUser: Model, FluentAuthUser, @unchecked Sendable {
    static let schema = "users"
    static let emailFieldKey: FieldKey = "email"

    @ID(key: .id) var id: UUID?
    @Field(key: "display_name") var displayName: String
    @Field(key: "email") var email: String
    @Field(key: "is_admin") var isAdmin: Bool
    @Timestamp(key: "created_at", on: .create) var createdAt: Date?

    init() {}

    required init(displayName: String, email: String) {
        self.displayName = displayName
        self.email = email
        self.isAdmin = false
    }
}
```

The library does not own the User table. Your app creates it and conforms the model to `FluentAuthUser`.

### 2. Define your request context

```swift
import Hummingbird
import HummingbirdAuth

struct AppContext: CSRFProtectedContext, RequestContext {
    typealias User = AppUser

    var coreContext: CoreRequestContextStorage
    var user: AppUser?
    var flashMessages: [FlashMessage] = []
    var masqueradingAs: String?
    var realUserID: UUID?
    var csrfToken: String?
    var csrfSkipped: Bool = false

    init(source: ApplicationRequestContextSource) {
        self.coreContext = .init(source: source)
    }
}
```

Conforming to `CSRFProtectedContext` (a marker refinement of
`AuthRequestContextProtocol`) is required by all the route installers —
see [CSRF Protection](#csrf-protection) below.

### 3. Register migrations

```swift
// Your app's User table must be created first
await fluent.migrations.add(CreateUsers())

// Then the auth library tables (pass your User table's schema name)
await addAuthMigrations(to: fluent, userTable: AppUser.schema)
```

### 4. Configure and install

```swift
let router = Router(context: AppContext.self)
let db = fluent.db()

let authConfig = AuthConfiguration<AppUser>(
    passkey: PasskeyConfiguration(
        relyingPartyID: "example.com",
        relyingPartyName: "My App",
        relyingPartyOrigin: "https://example.com"
    ),
    session: SessionConfiguration(secureCookie: true),
    invitations: InvitationConfiguration(),
    callbacks: AuthCallbacks(postLoginRedirect: { _ in "/" })
)

// Middleware
router.add(middleware: SessionMiddleware<AppContext>(db: db, config: authConfig.session))
router.add(middleware: CSRFMiddleware<AppContext>())
router.add(middleware: AuthRedirectMiddleware<AppContext>(loginPath: "/login"))

// Auth ceremony routes (POST /auth/begin-login, /auth/finish-login, etc.)
installAuthRoutes(on: router, db: db, config: authConfig, logger: logger)
```

### 5. Add login and registration pages

The library provides embeddable Plot components. Wrap them in your app's layout:

```swift
import HummingbirdAuthViews

// Include WebAuthnScript.scriptTag in your page's <head>
router.get("/login") { request, context -> MyPageLayout in
    MyPageLayout(title: "Sign In", includeAuthScript: true) {
        LoginView(pathPrefix: "/auth")
    }
}

router.get("/invite/:token") { request, context -> MyPageLayout in
    let token = context.parameters.get("token") ?? ""
    MyPageLayout(title: "Create Account", includeAuthScript: true) {
        RegistrationView(invitationToken: token, pathPrefix: "/auth")
    }
}
```

Or use the standalone pages for a quick setup:

```swift
router.get("/login") { _, _ -> HTML in
    StandaloneLoginPage(title: "Sign In", stylesheetURL: "/styles.css").html
}
```

### 6. Protect routes with authentication

```swift
let authed = router.group(context: AuthenticatedContext<AppContext>.self)

// These routes require login (401 → redirect to /login)
authed.get("/dashboard") { _, context -> Response in
    let user = context.user  // Non-optional, guaranteed present
    // ...
}
```

### 7. Add profile and admin routes

```swift
// Profile editing
installProfileRoutes(on: authed, db: db) { vm, context in
    MyPageLayout(title: "Profile") { ProfileView(viewModel: vm) }
}

// Admin (users, invitations, masquerade)
let admin = router.group(context: AdminContext<AppContext>.self)
installAdminRoutes(
    on: admin, db: db, logger: logger,
    config: AdminRouteConfiguration(baseURL: "https://example.com"),
    renderUsers: { users, ctx in
        MyPageLayout(title: "Users") {
            AdminUsersView(users: users, csrfToken: ctx.csrfToken)
        }
    },
    renderInvitations: { invitations, baseURL, ctx in
        MyPageLayout(title: "Invitations") {
            AdminInvitationsView(invitations: invitations, baseURL: baseURL,
                                 csrfToken: ctx.csrfToken)
        }
    }
)
```

## CSRF Protection

The library enforces CSRF protection by default via `CSRFMiddleware`. Every state-changing, cookie-authenticated request must echo the session's `csrfToken` back — either as a `csrf_token` form field or as an `X-CSRF-Token` HTTP header. Mismatches are rejected with a `403 Forbidden`.

The route installers require a `CSRFProtectedContext` — directly for `installAuthRoutes`, `installAdminRoutes`, and `installProfileRoutes`, and transitively via `OAuthRequestContextProtocol` (which refines `CSRFProtectedContext`) for `installOAuthRoutes`. Apps that don't install `CSRFMiddleware` — or don't conform their context — get a compile error rather than a silently-insecure default.

### Installing the middleware

Add `CSRFMiddleware` after `SessionMiddleware` (and, if you use the OAuth layer, after `OAuthBearerMiddleware`):

```swift
router.add(middleware: SessionMiddleware<AppContext>(db: db))
router.add(middleware: OAuthBearerMiddleware<AppContext>(oauthService: oauth))  // if using OAuth
router.add(middleware: CSRFMiddleware<AppContext>())
```

### Skip conditions

`CSRFMiddleware` intentionally does nothing for requests that have nothing to forge against:

- Safe methods (`GET`, `HEAD`, `OPTIONS`).
- Requests that arrive with an `Authorization: Bearer …` header (bearer-token authentication is immune to CSRF by construction).
- Requests with no session cookie (unauthenticated — nothing to forge against).
- Requests explicitly opted out via `SkipCSRF` (see [Opting out](#opting-out) below).

### Where to read the token

- `application/x-www-form-urlencoded` → the middleware reads `csrf_token` from the collected form body. Hummingbird's `collectBody(upTo:)` buffers the body back onto the request so downstream handlers can decode it normally.
- Any other content type (JSON, HTMX / fetch / XHR, `multipart/form-data`): the `X-CSRF-Token` header is the only accepted source. Multipart bodies are intentionally not parsed — apps uploading multipart data must set the header via the HTMX `hx-headers` attribute or a `fetch()` `headers` object.

### Embedding the token in forms

Use the `CSRFField` Plot component from `HummingbirdAuthViews` in every state-changing form:

```swift
import HummingbirdAuthViews

Element(name: "form") {
    CSRFField(context.csrfToken)
    // … other inputs …
}
.attribute(named: "method", value: "POST")
.attribute(named: "action", value: "/some/endpoint")
```

For HTMX-driven mutations that don't carry a form body (`hx-post` / `hx-delete` / `hx-patch` with JSON), include `CSRFMetaTag` and `CSRFHTMXScript.scriptTag` in your layout's `<head>` once. The script registers an `htmx:configRequest` listener that adds `X-CSRF-Token` to every outgoing HTMX request — including elements added dynamically — reading the token from the meta tag:

```swift
.head(
    .title(title),
    csrfMetaTag(context.csrfToken),
    .raw(CSRFHTMXScript.scriptTag)
)
```

Plain-JS `fetch()` callers that perform mutations can read the same meta tag and set the `X-CSRF-Token` header themselves.

### Opting out

Some routes genuinely don't need CSRF protection — for example external webhook receivers (which authenticate with a signature header, not a session cookie). Use `SkipCSRF`, but place it *outside* `CSRFMiddleware` so the flag is visible when the middleware checks it:

```swift
let webhooks = router.group("")
    .add(middleware: SkipCSRF<AppContext>())
    .add(middleware: CSRFMiddleware<AppContext>())
webhooks.post("/webhooks/stripe") { request, context in /* … */ }
```

The simpler pattern is to install `CSRFMiddleware` on a group that covers your protected routes and leave webhook routes outside it entirely. `SkipCSRF` is only necessary when you must install `CSRFMiddleware` globally.

## Cookie Path Scoping

When running multiple apps behind the same domain with path-based ingress routing, set the cookie path to prevent session conflicts:

```swift
SessionConfiguration(cookiePath: "/myapp", secureCookie: true)
```

The cookie name is fixed as `hb-auth` and is not configurable.

## Creating the First User

Use a CLI subcommand or insert an invitation directly:

```swift
// In your app's CLI:
let invitationService = InvitationService(db: db, logger: logger)
let invitation = try await invitationService.createInvitation(email: "admin@example.com")
print("Register at: https://example.com/invite/\(invitation.token)")
```

## License

MIT
