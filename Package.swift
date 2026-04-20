// swift-tools-version: 6.2

import PackageDescription

let package = Package(
    name: "hummingbird-auth",
    platforms: [
        .macOS(.v15),
    ],
    products: [
        .library(name: "HummingbirdAuthCore", targets: ["HummingbirdAuthCore"]),
        .library(name: "HummingbirdAuth", targets: ["HummingbirdAuth"]),
        .library(name: "HummingbirdAuthViews", targets: ["HummingbirdAuthViews"]),
        .library(name: "HummingbirdAuthOAuth", targets: ["HummingbirdAuthOAuth"]),
    ],
    dependencies: [
        .package(url: "https://github.com/hummingbird-project/hummingbird.git", from: "2.0.0"),
        .package(url: "https://github.com/hummingbird-project/hummingbird-fluent.git", from: "2.0.0"),
        .package(url: "https://github.com/swift-server/webauthn-swift.git", branch: "main"),
        .package(url: "https://github.com/samalone/Plot.git", branch: "samalone/all-fixes"),
        .package(url: "https://github.com/samalone/plot-htmx.git", branch: "main"),
        .package(url: "https://github.com/vapor/fluent-sqlite-driver.git", from: "4.0.0"),
        // swift-crypto provides a portable CSPRNG (wraps SecRandomCopyBytes
        // on Apple, getrandom(2)/urandom on Linux) so the same code builds
        // for macOS dev and Linux containers.
        .package(url: "https://github.com/apple/swift-crypto.git", "2.0.0"..<"5.0.0"),
    ],
    targets: [
        // Layer 1: Protocols, configuration, view models, and plain DTOs.
        // No Fluent dependency — Core is intentionally runtime-framework-free
        // so it can be imported by non-Fluent callers.
        .target(
            name: "HummingbirdAuthCore",
            dependencies: [
                .product(name: "Hummingbird", package: "hummingbird"),
                .product(name: "Crypto", package: "swift-crypto"),
            ]
        ),

        // Layer 2: Fluent models, services, middleware, route installers
        .target(
            name: "HummingbirdAuth",
            dependencies: [
                "HummingbirdAuthCore",
                .product(name: "Hummingbird", package: "hummingbird"),
                .product(name: "HummingbirdFluent", package: "hummingbird-fluent"),
                .product(name: "WebAuthn", package: "webauthn-swift"),
            ]
        ),

        // Layer 3: Plot HTML components for login, registration, admin
        .target(
            name: "HummingbirdAuthViews",
            dependencies: [
                "HummingbirdAuthCore",
                .product(name: "Plot", package: "Plot"),
                .product(name: "PlotHTMX", package: "plot-htmx"),
            ]
        ),

        // Layer 4: OAuth 2.1 authorization server
        .target(
            name: "HummingbirdAuthOAuth",
            dependencies: [
                "HummingbirdAuth",
                .product(name: "Hummingbird", package: "hummingbird"),
                .product(name: "HummingbirdFluent", package: "hummingbird-fluent"),
            ]
        ),

        .testTarget(
            name: "HummingbirdAuthTests",
            dependencies: [
                "HummingbirdAuth",
                "HummingbirdAuthCore",
                "HummingbirdAuthViews",
                .product(name: "FluentSQLiteDriver", package: "fluent-sqlite-driver"),
                .product(name: "HummingbirdTesting", package: "hummingbird"),
                .product(name: "Plot", package: "Plot"),
            ]
        ),
    ]
)
