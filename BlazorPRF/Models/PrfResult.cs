namespace BlazorPRF.Models;

/// <summary>
/// Derived keys result from PRF evaluation.
/// </summary>
/// <param name="PrivateKeyBase64">The private key (Base64) - sensitive!</param>
/// <param name="PublicKeyBase64">The public key (Base64) - can be shared.</param>
public sealed record DerivedKeysResult(
    string PrivateKeyBase64,
    string PublicKeyBase64
);

/// <summary>
/// Derived keys result with credential ID from discoverable credential.
/// </summary>
/// <param name="CredentialId">The credential ID that was used (Base64).</param>
/// <param name="PrivateKeyBase64">The private key (Base64) - sensitive!</param>
/// <param name="PublicKeyBase64">The public key (Base64) - can be shared.</param>
public sealed record DiscoverableDerivedKeysResult(
    string CredentialId,
    string PrivateKeyBase64,
    string PublicKeyBase64
);
