import Plot

/// A complete standalone login HTML page.
///
/// For apps that don't need a custom PageLayout on their login page.
/// Includes the WebAuthn script automatically.
public struct StandaloneLoginPage {
    public var title: String
    public var errorMessage: String?
    public var returnURL: String?
    public var pathPrefix: String
    public var stylesheetURL: String?

    public init(
        title: String = "Sign In",
        errorMessage: String? = nil,
        returnURL: String? = nil,
        pathPrefix: String = "/auth",
        stylesheetURL: String? = nil
    ) {
        self.title = title
        self.errorMessage = errorMessage
        self.returnURL = returnURL
        self.pathPrefix = pathPrefix
        self.stylesheetURL = stylesheetURL
    }

    public var html: HTML {
        HTML(
            .head(
                .meta(.charset(.utf8)),
                .meta(.name("viewport"), .content("width=device-width, initial-scale=1")),
                .title(title),
                .unwrap(stylesheetURL) { .stylesheet($0) },
                .raw(WebAuthnScript.scriptTag)
            ),
            .body(
                .class("auth-page"),
                .div(
                    .class("auth-card"),
                    .component(LoginView(
                        errorMessage: errorMessage,
                        returnURL: returnURL,
                        pathPrefix: pathPrefix
                    ))
                )
            )
        )
    }
}

/// A complete standalone registration HTML page.
///
/// For apps that don't need a custom PageLayout on their registration page.
/// Includes the WebAuthn script automatically.
public struct StandaloneRegistrationPage {
    public var title: String
    public var invitationToken: String
    public var email: String?
    public var errorMessage: String?
    public var pathPrefix: String
    public var stylesheetURL: String?

    public init(
        title: String = "Create Account",
        invitationToken: String,
        email: String? = nil,
        errorMessage: String? = nil,
        pathPrefix: String = "/auth",
        stylesheetURL: String? = nil
    ) {
        self.title = title
        self.invitationToken = invitationToken
        self.email = email
        self.errorMessage = errorMessage
        self.pathPrefix = pathPrefix
        self.stylesheetURL = stylesheetURL
    }

    public var html: HTML {
        HTML(
            .head(
                .meta(.charset(.utf8)),
                .meta(.name("viewport"), .content("width=device-width, initial-scale=1")),
                .title(title),
                .unwrap(stylesheetURL) { .stylesheet($0) },
                .raw(WebAuthnScript.scriptTag)
            ),
            .body(
                .class("auth-page"),
                .div(
                    .class("auth-card"),
                    .component(RegistrationView(
                        invitationToken: invitationToken,
                        email: email,
                        errorMessage: errorMessage,
                        pathPrefix: pathPrefix
                    ))
                )
            )
        )
    }
}
