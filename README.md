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

struct AppContext: AuthRequestContextProtocol, RequestContext {
    typealias User = AppUser

    var coreContext: CoreRequestContextStorage
    var user: AppUser?
    var flashMessages: [FlashMessage] = []
    var masqueradingAs: String?
    var realUserID: UUID?
    var csrfToken: String?

    init(source: ApplicationRequestContextSource) {
        self.coreContext = .init(source: source)
    }
}
```

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

All form POST endpoints (profile update, admin role changes, masquerade, invitation management) validate a per-session CSRF token. Pass `csrfToken` from the context to the view components so they can include it as a hidden form field:

```swift
ProfileView(viewModel: vm)                  // csrfToken is in the view model
AdminUsersView(users: users, csrfToken: ctx.csrfToken)
AdminInvitationsView(invitations: invs, baseURL: url, csrfToken: ctx.csrfToken)
```

If your app renders its own "end masquerade" button, include the token as a hidden field:

```html
<form method="POST" action="/admin/masquerade/end">
    <input type="hidden" name="csrf_token" value="{{csrfToken}}">
    <button type="submit">End Masquerade</button>
</form>
```

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
