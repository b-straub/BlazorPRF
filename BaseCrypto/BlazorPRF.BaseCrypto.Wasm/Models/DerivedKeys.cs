namespace BlazorPRF.BaseCrypto.Wasm.Models;

/// <summary>
/// Result from PRF authentication.
/// Contains only public information - private keys remain in JavaScript.
/// </summary>
/// <param name="CredentialIdBase64">Credential ID used for authentication</param>
/// <param name="PublicKeyBase64">32-byte Ed25519 public key for signature verification</param>
public sealed record AuthResult(
    string CredentialIdBase64,
    string PublicKeyBase64
);
