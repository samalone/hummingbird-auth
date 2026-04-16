# Security Audit — 2026-04-16

Findings from security reviews of the hummingbird-auth library.
Work through these in priority order. Check off each item as fixed.

## Critical

- [x] **Session tokens use UUID instead of generateSecureToken()** — `AuthRouteInstaller.swift` lines 77, 181. `UUID().uuidString` has only 122 bits of entropy; `generateSecureToken()` (256 bits) already exists. Swap both occurrences.

- [x] **No redirect URI validation in createAuthorizationCode** — `OAuthService.swift` lines 103-124. The method accepts any redirect URI without checking it against the client's registered `redirectURIList`. Add: `guard client.redirectURIList.contains(redirectURI)`.

## High

- [x] **Scope not validated at auth code creation** — `OAuthService.swift` lines 103-124. `createAuthorizationCode` stores scopes without checking they're a subset of the client's registered scopes or `config.validScopes`. Also, `refreshAccessToken` copies old scopes without re-validating.

- [x] **Challenge not bound to ceremony type** — `PasskeyService.swift` `verifyChallenge()` looks up by value only, ignoring the `type` field. A registration challenge could be used in an authentication flow. Add a `type` parameter and filter on it.

- [x] **Auth code replay via TOCTOU race** — `OAuthService.swift` lines 141-160. Two concurrent requests with the same code can both pass `!isConsumed` before either sets `consumedAt`. Use atomic conditional update: `UPDATE ... WHERE consumed_at IS NULL`.

- [x] **Unauthenticated client registration** — `OAuthRouteInstaller.swift` lines 51-83. `/oauth/register` has no auth, no rate limit. Anyone can register unlimited clients with arbitrary redirect URIs. Either require admin auth or document this as intentional for the use case.

## Medium

- [x] **Invitation consumption race condition** — `InvitationService.swift` + `AuthRouteInstaller.swift`. Same TOCTOU pattern as auth code: two concurrent registrations can both consume the same invitation. Use atomic conditional update.

- [ ] **Expired cookie missing security attributes** — `SessionMiddleware.swift` `expiredAuthSession()`. Missing `secure`, `httpOnly`, `sameSite` attributes that the set cookie has. Browser may treat them as different cookies, leaving the original intact.

- [ ] **Masquerade persists after admin demotion** — `AuthRequestContext.swift` line 78. `AdminContext` trusts `realUserID != nil` without re-validating that the real user is still an admin. If demoted mid-masquerade, admin access persists. Re-validate in SessionMiddleware when masquerade is active.

- [ ] **Open redirect backslash edge case** — `AuthRouteInstaller.swift` `validateReturnURL`. Does not reject paths containing backslashes (e.g., `/\evil.com`) which some browsers normalize to `//evil.com`. Add `!url.contains("\\")`.

- [ ] **No rate limiting on token endpoint** — `OAuthRouteInstaller.swift`. Unlimited brute-force attempts against `/oauth/token`. Infrastructure concern but worth noting.

## Low

- [ ] **Error messages leak user existence** — `AuthRouteInstaller.swift` lines 60, 73, 157. Distinct errors for "Unknown credential", "User not found", "A user with this email already exists" enable enumeration. Consider generic error messages.

- [ ] **SecRandomCopyBytes return value not checked** — `Utilities.swift` line 9. Failure would produce a zero token. Check return value and throw on failure.

- [ ] **Body size limit too generous** — `AuthRouteInstaller.swift` lines 42, 112, 133. 1 MB for WebAuthn payloads that are typically <10 KB. Reduce to 128 KB.

- [ ] **Sign count validation** — `PasskeyService.swift` lines 131-139. No explicit check that `newSignCount > credentialCurrentSignCount`. Verify what swift-webauthn enforces internally.

- [ ] **Flash message text not sanitized** — `AuthSession.addFlash()` is public API. If callers pass user-controlled text and views don't HTML-escape, it's stored XSS. Document the contract.

- [ ] **Profile fields not validated** — `ProfileRouteInstaller.swift` lines 42-43. No length limit on displayName, no format validation on email.

## Second Review — 2026-04-16 (full codebase)

### High (fixed)

- [x] **No CSRF protection on form POST endpoints** — Admin routes (role change, masquerade, invitation CRUD) and profile update accepted form POSTs with no anti-forgery tokens. Added per-session CSRF tokens stored in `AuthSession`, populated in context by `SessionMiddleware`, validated on all form POST handlers, and rendered as hidden fields in all view components.

- [x] **Registration email/identity not bound to challenge** — `begin-registration` and `finish-registration` both accepted email/displayName/invitationToken as separate client inputs. An attacker could swap the email between begin and finish to bind their passkey to a different account. Fixed by storing registration context (email, displayName, invitationToken) in `PasskeyChallenge` at begin time and reading it back at finish time. `FinishRegistrationRequest` no longer accepts these fields from the client.

### Medium (fixed)

- [x] **Invitation email constraint not enforced** — Invitations created for a specific email did not verify that the registering user's email matched. Fixed: `begin-registration` now checks `invitation.email` against the submitted email (case-insensitive).

- [x] **Logout during masquerade destroyed target user's sessions** — Logout deleted all sessions matching `context.user.id`, which during masquerade is the target user's ID. Fixed: logout now deletes only the current session by filtering on the session token from the cookie.

- [x] **OAuth redirect URIs not validated for format or scheme** — `registerClient()` stored redirect URIs as-is with no validation. Fixed: redirect URIs must be absolute HTTP(S) URLs, must use HTTPS (HTTP allowed only for localhost/127.0.0.1/::1), and must not contain fragments.
