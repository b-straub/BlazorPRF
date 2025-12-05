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

/// <summary>
/// Raw PRF output with credential ID from discoverable credential.
/// Used for JS interop - key derivation happens in C#.
/// </summary>
/// <param name="CredentialId">The credential ID that was used (Base64).</param>
/// <param name="PrfOutput">The raw PRF output (Base64) - 32 bytes.</param>
public sealed record DiscoverablePrfOutput(
    string CredentialId,
    string PrfOutput
);
