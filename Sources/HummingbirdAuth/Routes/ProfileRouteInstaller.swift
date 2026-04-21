import FluentKit
import Foundation
import Hummingbird
import HummingbirdAuthCore
import Logging

struct ProfileInput: Decodable {
    var display_name: String
    var email: String
}

/// Install profile routes.
///
/// - `GET /profile` — show the profile form
/// - `POST /profile` — update display name and email
///
/// Routes land under whatever `RouterGroup` is passed in, so apps mounted on
/// a sub-path can pass e.g. `router.group(RouterPath("/myapp")).group(context:
/// AuthenticatedContext<AppContext>.self)` and the profile routes will live at
/// `/myapp/profile`.
///
/// The `render` closure receives a `ProfileViewModel` and the request context,
/// and should return a `ResponseGenerator` (typically an `HTML` page wrapping
/// a `ProfileView` from HummingbirdAuthViews in your app's layout).
public func installProfileRoutes<Context: CSRFProtectedContext, Page: ResponseGenerator>(
    on router: RouterGroup<AuthenticatedContext<Context>>,
    db: Database,
    render: @escaping @Sendable (ProfileViewModel, AuthenticatedContext<Context>) -> Page
) where Context.User: FluentAuthUser {

    router.get("/profile") { request, context -> Response in
        let vm = ProfileViewModel(
            displayName: context.user.displayName,
            email: context.user.email,
            csrfToken: context.csrfToken
        )
        return try render(vm, context).response(from: request, context: context)
    }

    router.post("/profile") { request, context -> Response in
        let input = try await URLEncodedFormDecoder().decode(
            ProfileInput.self, from: request, context: context
        )

        guard var user = try await Context.User.find(context.user.id!, on: db) else {
            throw HTTPError(.notFound)
        }
        user.displayName = input.display_name.trimmingCharacters(in: .whitespacesAndNewlines)
        user.email = input.email.trimmingCharacters(in: .whitespacesAndNewlines)
        try await user.save(on: db)

        let vm = ProfileViewModel(
            displayName: user.displayName,
            email: user.email,
            savedMessage: "Profile updated.",
            csrfToken: context.csrfToken
        )
        return try render(vm, context).response(from: request, context: context)
    }
}
