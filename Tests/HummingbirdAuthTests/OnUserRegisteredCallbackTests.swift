import FluentKit
import FluentSQLiteDriver
import Foundation
import HummingbirdFluent
import Logging
import Testing

@testable import HummingbirdAuth
@testable import HummingbirdAuthCore

/// Verifies that the `AuthCallbacks.onUserRegistered` callback receives the
/// `Invitation` that was consumed during registration.
///
/// We can't easily exercise the full finish-registration HTTP handler from
/// a unit test (it requires a real WebAuthn credential ceremony with a
/// registered challenge). Instead we test the contract the route handler
/// depends on:
///
/// 1. `InvitationService.consumeInvitation` returns an `Invitation` whose
///    `consumedAt` is non-nil, whose `consumedByID` matches the user, and
///    whose `id`/`token` match the invitation that was passed in.
/// 2. The `AuthCallbacks.onUserRegistered` signature accepts
///    `(User, Invitation)` — the closure compiles and fires with both
///    arguments.
///
/// Together these cover the behavior apps (Life Balance) depend on: when
/// the callback fires, the invitation has its metadata filled in, so the
/// app can read `email`, `invitedByID`, `id`, and `consumedAt` to apply
/// invitation-specific side effects (e.g. task-share acceptance).
@Suite("AuthCallbacks.onUserRegistered passes consumed invitation")
struct OnUserRegisteredCallbackTests {

    /// Minimal user type that satisfies `AuthUser` — callback tests don't
    /// need a real Fluent user.
    struct StubUser: AuthUser, Sendable {
        typealias IDValue = UUID
        var id: UUID?
        var email: String
        var displayName: String
        var isAdmin: Bool
        var createdAt: Date?

        init(displayName: String, email: String) {
            self.id = UUID()
            self.email = email
            self.displayName = displayName
            self.isAdmin = false
            self.createdAt = Date()
        }
    }

    @Test("consumeInvitation returns an invitation with consumedAt set, matching id and token")
    func consumeReturnsUpdatedInvitation() async throws {
        let (fluent, service) = try await makeService()
        defer { Task { try? await fluent.shutdown() } }

        let originalToken = "test-token-\(UUID().uuidString)"
        let invitation = Invitation(
            token: originalToken,
            email: "invitee@example.com",
            invitedByID: nil,
            expiresAt: Date().addingTimeInterval(3600)
        )
        try await invitation.save(on: fluent.db())
        let invitationID = try invitation.requireID()

        let userID = try await insertStubUser(email: "consumer@example.com", on: fluent.db())
        let consumed = try await service.consumeInvitation(invitation, consumedByID: userID)

        #expect(consumed.id != nil)
        #expect(try consumed.requireID() == invitationID)
        #expect(consumed.token == originalToken)
        #expect(consumed.consumedAt != nil)
        #expect(consumed.consumedByID == userID)
        #expect(consumed.email == "invitee@example.com")
    }

    @Test("onUserRegistered callback signature accepts (User, Invitation) and receives matching invitation")
    func callbackReceivesInvitation() async throws {
        let (fluent, service) = try await makeService()
        defer { Task { try? await fluent.shutdown() } }

        let originalToken = "cb-token-\(UUID().uuidString)"
        let invitation = Invitation(
            token: originalToken,
            email: "cb@example.com",
            invitedByID: nil,
            expiresAt: Date().addingTimeInterval(3600)
        )
        try await invitation.save(on: fluent.db())

        // Record what the callback sees so we can assert on it after firing.
        actor Recorder {
            var capturedUserEmail: String?
            var capturedInvitationID: UUID?
            var capturedInvitationToken: String?
            var capturedConsumedAt: Date?

            func record(user: StubUser, invitation: Invitation) throws {
                self.capturedUserEmail = user.email
                self.capturedInvitationID = try invitation.requireID()
                self.capturedInvitationToken = invitation.token
                self.capturedConsumedAt = invitation.consumedAt
            }
        }
        let recorder = Recorder()

        // This is the signature we're verifying: (User, Invitation).
        var callbacks = AuthCallbacks<StubUser>()
        callbacks.onUserRegistered = { user, invitation in
            try await recorder.record(user: user, invitation: invitation)
        }

        // Simulate the route handler's flow: consume first, then fire callback
        // with the returned consumed invitation.
        let userID = try await insertStubUser(email: "cb@example.com", on: fluent.db())
        let user = StubUser(displayName: "Callback User", email: "cb@example.com")
        let consumed = try await service.consumeInvitation(invitation, consumedByID: userID)
        try await callbacks.onUserRegistered?(user, consumed)

        #expect(await recorder.capturedUserEmail == "cb@example.com")
        #expect(await recorder.capturedInvitationToken == originalToken)
        #expect(await recorder.capturedInvitationID != nil)
        // The invitation visible to the callback must have consumedAt set —
        // apps rely on this to know registration is finalized before they
        // apply side effects.
        #expect(await recorder.capturedConsumedAt != nil)
    }

    // MARK: - Helpers

    /// Build an in-memory Fluent instance plus an `InvitationService`
    /// pointed at it. Keeps the rest of the tests above focused on
    /// assertions rather than setup plumbing.
    private func makeService() async throws -> (Fluent, InvitationService) {
        var logger = Logger(label: "onuserregistered-callback-tests")
        logger.logLevel = .warning

        let fluent = Fluent(logger: logger)
        fluent.databases.use(.sqlite(.memory), as: .sqlite)
        // We only need the invitations table for these tests, but the
        // shared helper also sets up challenges/credentials/sessions —
        // harmless here.
        await addAuthMigrations(to: fluent, userTable: "users")
        // addAuthMigrations depends on a "users" table existing; create a
        // minimal one so the foreign-key references succeed on SQLite.
        await fluent.migrations.add(CreateStubUsersForCallbackTests())
        try await fluent.migrate()

        let service = InvitationService(
            db: fluent.db(), logger: logger, config: InvitationConfiguration()
        )
        return (fluent, service)
    }

    /// Insert a minimal user row into the stub `users` table and return its
    /// id. Used to satisfy the `consumed_by_id` foreign key on the
    /// invitations table when calling `consumeInvitation`.
    private func insertStubUser(email: String, on db: any Database) async throws -> UUID {
        let id = UUID()
        let user = StubUserModel(id: id, email: email, displayName: "Stub")
        try await user.save(on: db)
        return id
    }
}

/// A Fluent model backing the stub `users` table, used only to satisfy the
/// foreign-key reference from `auth_invitations.consumed_by_id`.
final class StubUserModel: Model, @unchecked Sendable {
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

    init(id: UUID, email: String, displayName: String) {
        self.id = id
        self.email = email
        self.displayName = displayName
        self.isAdmin = false
    }
}

/// Minimal users table so the auth migrations that reference it can
/// be applied cleanly against SQLite.
struct CreateStubUsersForCallbackTests: AsyncMigration {
    var name: String { "CreateStubUsersForCallbackTests" }

    func prepare(on database: Database) async throws {
        try await database.schema("users")
            .id()
            .field("email", .string, .required)
            .field("display_name", .string, .required)
            .field("is_admin", .bool, .required, .sql(.default(false)))
            .field("created_at", .datetime)
            .unique(on: "email")
            .create()
    }

    func revert(on database: Database) async throws {
        try await database.schema("users").delete()
    }
}
