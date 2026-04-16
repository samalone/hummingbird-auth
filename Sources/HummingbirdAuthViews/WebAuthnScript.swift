/// Provides the WebAuthn ceremony JavaScript for passkey login and registration.
///
/// Include `WebAuthnScript.scriptTag` in the `<head>` of any page that uses
/// `LoginView` or `RegistrationView`. The JS auto-wires to well-known element
/// IDs and reads the auth API path prefix from `data-auth-prefix` attributes.
///
/// Usage in your PageLayout:
/// ```swift
/// .head(
///     ...
///     .raw(WebAuthnScript.scriptTag)
/// )
/// ```
public enum WebAuthnScript {

    /// The complete WebAuthn ceremony JavaScript source.
    public static let source: String = """
    (function() {
        // Base64URL utilities
        function base64UrlToArrayBuffer(base64Url) {
            var base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
            var padding = base64.length % 4;
            if (padding) base64 += '===='.slice(padding);
            var binary = atob(base64);
            var bytes = new Uint8Array(binary.length);
            for (var i = 0; i < binary.length; i++) {
                bytes[i] = binary.charCodeAt(i);
            }
            return bytes.buffer;
        }

        function arrayBufferToBase64Url(buffer) {
            var binary = '';
            var bytes = new Uint8Array(buffer);
            for (var i = 0; i < bytes.length; i++) {
                binary += String.fromCharCode(bytes[i]);
            }
            return btoa(binary).replace(/\\+/g, '-').replace(/\\//g, '_').replace(/=/g, '');
        }

        function showError(message) {
            var el = document.getElementById('auth-error-message');
            if (el) {
                el.textContent = message;
                el.removeAttribute('hidden');
            }
        }

        function getAuthPrefix(element) {
            var container = element.closest('[data-auth-prefix]');
            return (container && container.dataset.authPrefix) || '/auth';
        }

        // Login ceremony
        async function beginPasskeyLogin(button, authPrefix) {
            button.disabled = true;
            button.textContent = 'Authenticating\\u2026';

            var returnURL = '';
            var returnEl = document.getElementById('auth-return-url');
            if (returnEl) returnURL = returnEl.value || '/';

            try {
                var beginResponse = await fetch(authPrefix + '/begin-login', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' }
                });
                if (!beginResponse.ok) throw new Error('Failed to start authentication');
                var beginData = await beginResponse.json();
                var publicKeyOptions = beginData.publicKey;
                var challengeBase64 = beginData.challengeBase64;

                var options = {
                    challenge: base64UrlToArrayBuffer(publicKeyOptions.challenge),
                    timeout: publicKeyOptions.timeout || 60000,
                    rpId: publicKeyOptions.rpId,
                    userVerification: publicKeyOptions.userVerification || 'preferred'
                };
                if (publicKeyOptions.allowCredentials) {
                    options.allowCredentials = publicKeyOptions.allowCredentials.map(function(c) {
                        return {
                            id: base64UrlToArrayBuffer(c.id),
                            type: c.type || 'public-key',
                            transports: c.transports || []
                        };
                    });
                }

                var credential = await navigator.credentials.get({ publicKey: options });

                var credentialJSON = JSON.stringify({
                    id: credential.id,
                    type: credential.type,
                    rawId: arrayBufferToBase64Url(credential.rawId),
                    response: {
                        clientDataJSON: arrayBufferToBase64Url(credential.response.clientDataJSON),
                        authenticatorData: arrayBufferToBase64Url(credential.response.authenticatorData),
                        signature: arrayBufferToBase64Url(credential.response.signature),
                        userHandle: credential.response.userHandle
                            ? arrayBufferToBase64Url(credential.response.userHandle)
                            : null
                    },
                    authenticatorAttachment: credential.authenticatorAttachment || null
                });

                var finishResponse = await fetch(authPrefix + '/finish-login', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        challengeBase64: challengeBase64,
                        credentialJSON: credentialJSON,
                        returnURL: returnURL
                    })
                });

                if (!finishResponse.ok) {
                    var errorText = await finishResponse.text().catch(function() { return ''; });
                    var errorMessage = 'Authentication failed';
                    try {
                        var errorData = JSON.parse(errorText);
                        errorMessage = errorData.message || errorData.reason || errorMessage;
                    } catch (e) {}
                    throw new Error(errorMessage);
                }

                var finishData = await finishResponse.json();
                window.location.href = finishData.redirectTo || '/';

            } catch (err) {
                button.disabled = false;
                button.textContent = 'Sign in with Passkey';
                if (err.name === 'NotAllowedError') {
                    showError('Authentication was cancelled or not allowed.');
                } else {
                    showError(err.message || 'An unexpected error occurred.');
                }
            }
        }

        // Registration ceremony
        async function beginPasskeyRegistration(form, button, authPrefix) {
            var displayName = document.getElementById('auth-display-name').value.trim();
            var email = document.getElementById('auth-email').value.trim();
            var invitationToken = document.getElementById('auth-invitation-token').value;

            if (!displayName || !email) {
                showError('Please fill in all fields.');
                return;
            }

            button.disabled = true;
            button.textContent = 'Creating account\\u2026';

            try {
                var beginResponse = await fetch(authPrefix + '/begin-registration', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        displayName: displayName,
                        email: email,
                        invitationToken: invitationToken
                    })
                });
                if (!beginResponse.ok) {
                    var errorText = await beginResponse.text().catch(function() { return ''; });
                    var errorMessage = 'Failed to start registration';
                    try {
                        var errorData = JSON.parse(errorText);
                        errorMessage = errorData.message || errorData.reason || errorMessage;
                    } catch (e) {}
                    throw new Error(errorMessage);
                }
                var beginData = await beginResponse.json();
                var publicKeyOptions = beginData.publicKey;
                var challengeBase64 = beginData.challengeBase64;

                var options = {
                    challenge: base64UrlToArrayBuffer(publicKeyOptions.challenge),
                    rp: publicKeyOptions.rp,
                    user: {
                        id: base64UrlToArrayBuffer(publicKeyOptions.user.id),
                        name: publicKeyOptions.user.name,
                        displayName: publicKeyOptions.user.displayName
                    },
                    pubKeyCredParams: publicKeyOptions.pubKeyCredParams || [],
                    timeout: publicKeyOptions.timeout || 300000,
                    attestation: publicKeyOptions.attestation || 'none',
                    authenticatorSelection: publicKeyOptions.authenticatorSelection
                };

                var credential = await navigator.credentials.create({ publicKey: options });

                var credentialCreationDataJSON = JSON.stringify({
                    id: credential.id,
                    type: credential.type,
                    rawId: arrayBufferToBase64Url(credential.rawId),
                    response: {
                        clientDataJSON: arrayBufferToBase64Url(credential.response.clientDataJSON),
                        attestationObject: arrayBufferToBase64Url(credential.response.attestationObject)
                    }
                });

                var finishResponse = await fetch(authPrefix + '/finish-registration', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        challengeBase64: challengeBase64,
                        credentialCreationDataJSON: credentialCreationDataJSON
                    })
                });

                if (!finishResponse.ok) {
                    var errorText = await finishResponse.text().catch(function() { return ''; });
                    var errorMessage = 'Registration failed';
                    try {
                        var errorData = JSON.parse(errorText);
                        errorMessage = errorData.message || errorData.reason || errorMessage;
                    } catch (e) {}
                    throw new Error(errorMessage);
                }

                var finishData = await finishResponse.json();
                window.location.href = finishData.redirectTo || '/';

            } catch (err) {
                button.disabled = false;
                button.textContent = 'Create Account with Passkey';
                if (err.name === 'NotAllowedError') {
                    showError('Registration was cancelled or not allowed.');
                } else if (err.name === 'InvalidStateError') {
                    showError('A passkey for this account already exists on this device.');
                } else {
                    showError(err.message || 'An unexpected error occurred.');
                }
            }
        }

        // Auto-wire on DOM ready
        document.addEventListener('DOMContentLoaded', function() {
            var loginBtn = document.getElementById('auth-login-button');
            if (loginBtn) {
                loginBtn.addEventListener('click', function() {
                    beginPasskeyLogin(loginBtn, getAuthPrefix(loginBtn));
                });
            }

            var regForm = document.getElementById('auth-registration-form');
            if (regForm) {
                regForm.addEventListener('submit', function(event) {
                    event.preventDefault();
                    var btn = regForm.querySelector('button[type="submit"]');
                    beginPasskeyRegistration(regForm, btn, getAuthPrefix(regForm));
                });
            }
        });
    })();
    """

    /// A `<script>` tag containing the WebAuthn ceremony JS.
    /// Use with `.raw()` in Plot's Node DSL.
    public static var scriptTag: String {
        "<script>\(source)</script>"
    }
}
