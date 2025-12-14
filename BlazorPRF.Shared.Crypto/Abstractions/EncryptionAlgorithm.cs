namespace BlazorPRF.Shared.Crypto.Abstractions;

/// <summary>
/// Symmetric encryption algorithms supported by BlazorPRF.
/// </summary>
public enum EncryptionAlgorithm
{
    /// <summary>
    /// ChaCha20-Poly1305 - Fast software implementation, not available in Web Crypto API.
    /// Supported by: BlazorPRF.Crypto (BouncyCastle)
    /// </summary>
    ChaCha20Poly1305,

    /// <summary>
    /// AES-256-GCM - Hardware accelerated via Web Crypto API.
    /// Supported by: BlazorPRF.Crypto (BouncyCastle), BlazorPRF.WebCrypto (SubtleCrypto)
    /// </summary>
    AesGcm
}
