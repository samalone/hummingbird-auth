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


<!-- BEGIN BEADS INTEGRATION v:1 profile:minimal hash:1105d646 -->
## Beads Issue Tracker

This project uses **bd (beads)** for issue tracking. Run `bd prime` to see full workflow context and commands.

### Quick Reference

```bash
bd ready              # Find available work
bd show <id>          # View issue details
bd update <id> --claim  # Claim work
bd close <id>         # Complete work
```

### Rules

- Use `bd` for ALL task tracking — do NOT use TodoWrite, TaskCreate, or markdown TODO lists
- Run `bd prime` for detailed command reference and session close protocol
- Use `bd remember` for persistent knowledge — do NOT use MEMORY.md files

**Architecture in one line:** issues live in a local Dolt DB; sync uses `refs/dolt/data` on your git remote; `.beads/issues.jsonl` is a passive export. See https://github.com/gastownhall/beads/blob/main/docs/core-concepts/sync-concepts.md for details and anti-patterns.

## Agent Context Profiles

The managed Beads block is task-tracking guidance, not permission to override repository, user, or orchestrator instructions.

- **Conservative (default)**: Use `bd` for task tracking. Do not run git commits, git pushes, or Dolt remote sync unless explicitly asked. At handoff, report changed files, validation, and suggested next commands.
- **Minimal**: Keep tool instruction files as pointers to `bd prime`; use the same conservative git policy unless active instructions say otherwise.
- **Team-maintainer**: Only when the repository explicitly opts in, agents may close beads, run quality gates, commit, and push as part of session close. A current "do not commit" or "do not push" instruction still wins.

## Session Completion

This protocol applies when ending a Beads implementation workflow. It is subordinate to explicit user, repository, and orchestrator instructions.

1. **File issues for remaining work** - Create beads for anything that needs follow-up
2. **Run quality gates** (if code changed) - Tests, linters, builds
3. **Update issue status** - Close finished work, update in-progress items
4. **Handle git/sync by active profile**:
   ```bash
   # Conservative/minimal/default: report status and proposed commands; wait for approval.
   git status

   # Team-maintainer opt-in only, unless current instructions forbid it:
   git pull --rebase
   git push
   git status
   ```
5. **Hand off** - Summarize changes, validation, issue status, and any blocked sync/commit/push step

**Critical rules:**
- Explicit user or orchestrator instructions override this Beads block.
- Do not commit or push without clear authority from the active profile or the current user request.
- If a required sync or push is blocked, stop and report the exact command and error.
<!-- END BEADS INTEGRATION -->

## Memory: beads vs. Claude Code auto-memory

`bd prime` says not to use MEMORY.md files. Disregard that blanket rule and
split by what the fact is *about*: `bd remember` for knowledge about this
repo (conventions, gotchas, decisions — it travels on `refs/dolt/data` and
any agent on any machine can read it; keep the count low, since prime injects
every memory in full every session), and Claude Code auto-memory under
`~/.claude/projects/<project>/memory/` for facts about me and how I want you
to work. Explicit user instructions override the beads block, as it concedes.
