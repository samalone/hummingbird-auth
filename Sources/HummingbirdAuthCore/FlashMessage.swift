/// A one-time notification message stored in the session and displayed
/// on the next page load.
public struct FlashMessage: Codable, Sendable, Equatable {
    public enum Level: String, Codable, Sendable {
        case success
        case info
        case warning
        case error
    }

    public let level: Level
    public let text: String

    public init(_ level: Level, _ text: String) {
        self.level = level
        self.text = text
    }
}
