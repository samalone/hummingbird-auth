import Crypto
import Foundation

/// Generate a cryptographically random 64-character hex token.
///
/// Used for session tokens, invitation tokens, OAuth client IDs,
/// authorization codes, and access/refresh tokens.
///
/// Uses `swift-crypto`'s `SymmetricKey(size:)`, which wraps the
/// platform CSPRNG (`SecRandomCopyBytes` on Apple platforms,
/// `getrandom(2)` / `/dev/urandom` on Linux). Portable across macOS
/// dev and Linux container builds.
public func generateSecureToken() -> String {
    let key = SymmetricKey(size: .bits256)
    return key.withUnsafeBytes { buffer in
        buffer.map { String(format: "%02x", $0) }.joined()
    }
}

/// Normalize any base64 string to base64url (no padding).
///
/// WebAuthn uses base64url throughout, but some libraries return standard
/// base64 in certain code paths. Always normalize before storing or comparing.
public func normalizeToBase64URL(_ value: String) -> String {
    value
        .replacingOccurrences(of: "+", with: "-")
        .replacingOccurrences(of: "/", with: "_")
        .replacingOccurrences(of: "=", with: "")
}

/// Encode data to base64url (no padding).
public func encodeBase64URL(_ data: Data) -> String {
    normalizeToBase64URL(data.base64EncodedString())
}

/// Decode a base64url string to bytes.
public func decodeBase64URL(_ base64url: String) throws -> [UInt8] {
    var base64 = base64url
        .replacingOccurrences(of: "-", with: "+")
        .replacingOccurrences(of: "_", with: "/")
    let remainder = base64.count % 4
    if remainder != 0 {
        base64 += String(repeating: "=", count: 4 - remainder)
    }
    guard let data = Data(base64Encoded: base64) else {
        throw Base64URLError.invalidEncoding
    }
    return Array(data)
}

public enum Base64URLError: Error {
    case invalidEncoding
}

public enum CSRFError: Error {
    case missingToken
    case invalidToken
}

/// Validate that a submitted CSRF token matches the session's CSRF token.
public func validateCSRFToken(submitted: String?, expected: String?) throws {
    guard let expected = expected else {
        throw CSRFError.missingToken
    }
    guard let submitted = submitted, submitted == expected else {
        throw CSRFError.invalidToken
    }
}
