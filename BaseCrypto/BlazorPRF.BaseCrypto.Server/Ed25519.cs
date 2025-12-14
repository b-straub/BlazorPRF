using System.Text;
using NSec.Cryptography;

namespace BlazorPRF.BaseCrypto.Server;

/// <summary>
/// Minimal Ed25519 sign/verify compatible with BlazorPRF.BaseCrypto.Wasm TypeScript implementation.
/// Uses NSec (libsodium wrapper).
/// </summary>
public static class Ed25519
{
    private static readonly SignatureAlgorithm Algorithm = SignatureAlgorithm.Ed25519;

    /// <summary>
    /// Verify a signature created by BlazorPRF.BaseCrypto.Wasm.
    /// </summary>
    /// <param name="message">Original UTF-8 message</param>
    /// <param name="signatureBase64">64-byte signature (Base64)</param>
    /// <param name="publicKeyBase64">32-byte public key (Base64)</param>
    /// <returns>True if signature is valid</returns>
    public static bool Verify(string message, string signatureBase64, string publicKeyBase64)
    {
        try
        {
            var messageBytes = Encoding.UTF8.GetBytes(message);
            var signatureBytes = Convert.FromBase64String(signatureBase64);
            var publicKeyBytes = Convert.FromBase64String(publicKeyBase64);

            if (signatureBytes.Length != 64 || publicKeyBytes.Length != 32)
            {
                return false;
            }

            var publicKey = PublicKey.Import(Algorithm, publicKeyBytes, KeyBlobFormat.RawPublicKey);
            return Algorithm.Verify(publicKey, messageBytes, signatureBytes);
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Sign a message using Ed25519 private key.
    /// </summary>
    /// <param name="message">UTF-8 message to sign</param>
    /// <param name="privateKeyBase64">32-byte private key seed (Base64)</param>
    /// <returns>64-byte signature (Base64)</returns>
    public static string Sign(string message, string privateKeyBase64)
    {
        var messageBytes = Encoding.UTF8.GetBytes(message);
        var privateKeyBytes = Convert.FromBase64String(privateKeyBase64);

        if (privateKeyBytes.Length != 32)
        {
            throw new ArgumentException("Private key must be 32 bytes", nameof(privateKeyBase64));
        }

        using var key = Key.Import(Algorithm, privateKeyBytes, KeyBlobFormat.RawPrivateKey);
        var signature = Algorithm.Sign(key, messageBytes);

        return Convert.ToBase64String(signature);
    }

    /// <summary>
    /// Derive public key from private key seed.
    /// </summary>
    /// <param name="privateKeyBase64">32-byte private key seed (Base64)</param>
    /// <returns>32-byte public key (Base64)</returns>
    public static string GetPublicKey(string privateKeyBase64)
    {
        var privateKeyBytes = Convert.FromBase64String(privateKeyBase64);

        if (privateKeyBytes.Length != 32)
        {
            throw new ArgumentException("Private key must be 32 bytes", nameof(privateKeyBase64));
        }

        using var key = Key.Import(Algorithm, privateKeyBytes, KeyBlobFormat.RawPrivateKey);
        var publicKeyBytes = key.Export(KeyBlobFormat.RawPublicKey);

        return Convert.ToBase64String(publicKeyBytes);
    }

    /// <summary>
    /// Generate a new random Ed25519 key pair.
    /// </summary>
    /// <returns>Tuple of (privateKeyBase64, publicKeyBase64)</returns>
    public static (string PrivateKey, string PublicKey) GenerateKeyPair()
    {
        using var key = Key.Create(Algorithm, new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextExport });

        var privateKeyBytes = key.Export(KeyBlobFormat.RawPrivateKey);
        var publicKeyBytes = key.Export(KeyBlobFormat.RawPublicKey);

        return (Convert.ToBase64String(privateKeyBytes), Convert.ToBase64String(publicKeyBytes));
    }
}
