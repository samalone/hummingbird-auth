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
    ],
    dependencies: [
        .package(url: "https://github.com/hummingbird-project/hummingbird.git", from: "2.0.0"),
        .package(url: "https://github.com/hummingbird-project/hummingbird-fluent.git", from: "2.0.0"),
        .package(url: "https://github.com/swift-server/webauthn-swift.git", branch: "main"),
        .package(url: "https://github.com/samalone/Plot.git", branch: "samalone/all-fixes"),
        .package(url: "https://github.com/samalone/plot-htmx.git", branch: "main"),
        .package(url: "https://github.com/vapor/fluent-sqlite-driver.git", from: "4.0.0"),
    ],
    targets: [
        // Layer 1: Protocols and configuration — no Fluent dependency
        .target(
            name: "HummingbirdAuthCore",
            dependencies: [
                .product(name: "Hummingbird", package: "hummingbird"),
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

        .testTarget(
            name: "HummingbirdAuthTests",
            dependencies: [
                "HummingbirdAuth",
                "HummingbirdAuthCore",
                .product(name: "FluentSQLiteDriver", package: "fluent-sqlite-driver"),
            ]
        ),
    ]
)
