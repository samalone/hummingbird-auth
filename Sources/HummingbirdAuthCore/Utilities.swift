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

// MARK: - CSRF token constants

/// Form field name that carries the CSRF token in
/// `application/x-www-form-urlencoded` bodies. Single source of truth for
/// both `CSRFMiddleware` (which reads it from the form body) and the
/// `CSRFField` view component (which emits the hidden input).
public let csrfFormFieldName = "csrf_token"

/// HTTP request header name that carries the CSRF token for non-form
/// requests (JSON, HTMX, fetch, XHR, multipart). Single source of truth
/// for both `CSRFMiddleware` (which reads the header) and
/// `CSRFHTMXScript` (which injects the header on every HTMX request).
public let csrfHeaderName = "X-CSRF-Token"
