// swift-tools-version: 6.0

import PackageDescription

let package = Package(
    name: "HushWireMac",
    platforms: [
        .macOS(.v14)
    ],
    products: [
        .executable(name: "HushWireMac", targets: ["HushWireMac"])
    ],
    targets: [
        .executableTarget(
            name: "HushWireMac",
            path: "Sources/HushWireMac"
        ),
        .testTarget(
            name: "HushWireMacTests",
            dependencies: ["HushWireMac"],
            path: "Tests/HushWireMacTests"
        )
    ],
    swiftLanguageModes: [.v5]
)
