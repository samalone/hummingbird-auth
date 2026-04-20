import FluentKit
import FluentSQLiteDriver
import Foundation
import HummingbirdFluent
import Logging
import Testing

@testable import HummingbirdAuth
@testable import HummingbirdAuthCore

/// Verifies that the `AuthCallbacks.onUserRegistered` callback receives a
/// `ConsumedInvitation` DTO describing the invitation that was consumed
/// during registration.
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
///    `(User, ConsumedInvitation)` — the closure compiles and fires with
///    both arguments, where `ConsumedInvitation` is a plain-Swift DTO
///    built from the Fluent model by the route installer.
///
/// Together these cover the behavior apps (Life Balance) depend on: when
/// the callback fires, the DTO has its metadata filled in, so the app
/// can read `email`, `invitedByID`, `id`, and `consumedAt` to apply
/// invitation-specific side effects (e.g. task-share acceptance) without
/// ever touching a Fluent model.
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

    @Test("onUserRegistered callback signature accepts (User, ConsumedInvitation) and receives matching DTO")
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
        let invitationID = try invitation.requireID()

        // Record what the callback sees so we can assert on it after firing.
        actor Recorder {
            var capturedUserEmail: String?
            var capturedInvitationID: UUID?
            var capturedInvitationToken: String?
            var capturedEmail: String?
            var capturedConsumedByID: UUID?

            func record(user: StubUser, dto: ConsumedInvitation) {
                self.capturedUserEmail = user.email
                self.capturedInvitationID = dto.id
                self.capturedInvitationToken = dto.token
                self.capturedEmail = dto.email
                self.capturedConsumedByID = dto.consumedByID
            }
        }
        let recorder = Recorder()

        // This is the signature we're verifying: (User, ConsumedInvitation).
        var callbacks = AuthCallbacks<StubUser>()
        callbacks.onUserRegistered = { user, dto in
            await recorder.record(user: user, dto: dto)
        }

        // Simulate the route handler's flow: consume first, translate to
        // the DTO, then fire the callback with that DTO. This mirrors
        // what `AuthRouteInstaller` does after a successful registration.
        let userID = try await insertStubUser(email: "cb@example.com", on: fluent.db())
        let user = StubUser(displayName: "Callback User", email: "cb@example.com")
        let consumed = try await service.consumeInvitation(invitation, consumedByID: userID)
        let dto = ConsumedInvitation(
            id: try consumed.requireID(),
            token: consumed.token,
            email: consumed.email,
            invitedByID: consumed.invitedByID,
            expiresAt: consumed.expiresAt,
            consumedAt: try #require(consumed.consumedAt),
            consumedByID: try #require(consumed.consumedByID)
        )
        try await callbacks.onUserRegistered?(user, dto)

        #expect(await recorder.capturedUserEmail == "cb@example.com")
        #expect(await recorder.capturedInvitationToken == originalToken)
        #expect(await recorder.capturedInvitationID == invitationID)
        #expect(await recorder.capturedEmail == "cb@example.com")
        #expect(await recorder.capturedConsumedByID == userID)
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
