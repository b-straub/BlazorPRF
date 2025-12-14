namespace BlazorPRF.Shared.Crypto.Models;

/// <summary>
/// Contains both encryption (X25519) and signing (Ed25519) public keys
/// derived from the same PRF seed using different HKDF contexts.
/// </summary>
public sealed record DualKeyPair(
    /// <summary>Base64-encoded X25519 public key for ECIES encryption.</summary>
    string X25519PublicKey,
    /// <summary>Base64-encoded Ed25519 public key for digital signatures.</summary>
    string Ed25519PublicKey
);

/// <summary>
/// Contains both encryption (X25519) and signing (Ed25519) key pairs (private + public).
/// </summary>
public sealed record DualKeyPairFull(
    /// <summary>Base64-encoded X25519 private key.</summary>
    string X25519PrivateKey,
    /// <summary>Base64-encoded X25519 public key.</summary>
    string X25519PublicKey,
    /// <summary>Base64-encoded Ed25519 private key (32-byte seed).</summary>
    string Ed25519PrivateKey,
    /// <summary>Base64-encoded Ed25519 public key.</summary>
    string Ed25519PublicKey
)
{
    /// <summary>
    /// Gets just the public keys.
    /// </summary>
    public DualKeyPair PublicKeys => new(X25519PublicKey, Ed25519PublicKey);
}
