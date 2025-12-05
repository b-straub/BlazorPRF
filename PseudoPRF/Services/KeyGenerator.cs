using System.Security.Cryptography;
using BlazorPRF.Shared.Models;
using NSec.Cryptography;

namespace PseudoPRF.Services;

/// <summary>
/// Generates X25519 key pairs compatible with BlazorPRF.
/// </summary>
public static class KeyGenerator
{
    /// <summary>
    /// Generates a new random X25519 key pair.
    /// </summary>
    /// <returns>A new key pair with Base64-encoded keys.</returns>
    public static KeyPair GenerateKeyPair()
    {
        using var key = Key.Create(KeyAgreementAlgorithm.X25519, new KeyCreationParameters
        {
            ExportPolicy = KeyExportPolicies.AllowPlaintextExport
        });

        var privateKeyBytes = key.Export(KeyBlobFormat.RawPrivateKey);
        var publicKeyBytes = key.PublicKey.Export(KeyBlobFormat.RawPublicKey);

        return new KeyPair(
            PrivateKeyBase64: Convert.ToBase64String(privateKeyBytes),
            PublicKeyBase64: Convert.ToBase64String(publicKeyBytes)
        );
    }

    /// <summary>
    /// Derives the public key from a private key.
    /// </summary>
    /// <param name="privateKeyBase64">The private key (Base64, 32 bytes)</param>
    /// <returns>The corresponding public key (Base64, 32 bytes)</returns>
    /// <exception cref="ArgumentException">If the private key is invalid</exception>
    public static string GetPublicKey(string privateKeyBase64)
    {
        var privateKeyBytes = Convert.FromBase64String(privateKeyBase64);
        if (privateKeyBytes.Length != 32)
        {
            throw new ArgumentException("Private key must be 32 bytes", nameof(privateKeyBase64));
        }

        using var key = Key.Import(KeyAgreementAlgorithm.X25519, privateKeyBytes, KeyBlobFormat.RawPrivateKey);
        var publicKeyBytes = key.PublicKey.Export(KeyBlobFormat.RawPublicKey);

        return Convert.ToBase64String(publicKeyBytes);
    }

    /// <summary>
    /// Validates that a Base64 string is a valid X25519 public key.
    /// </summary>
    /// <param name="publicKeyBase64">The public key to validate</param>
    /// <returns>True if valid, false otherwise</returns>
    public static bool IsValidPublicKey(string publicKeyBase64)
    {
        try
        {
            var bytes = Convert.FromBase64String(publicKeyBase64);
            if (bytes.Length != 32)
            {
                return false;
            }

            // Try to import as public key
            _ = PublicKey.Import(KeyAgreementAlgorithm.X25519, bytes, KeyBlobFormat.RawPublicKey);
            return true;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Validates that a Base64 string is a valid X25519 private key.
    /// </summary>
    /// <param name="privateKeyBase64">The private key to validate</param>
    /// <returns>True if valid, false otherwise</returns>
    public static bool IsValidPrivateKey(string privateKeyBase64)
    {
        try
        {
            var bytes = Convert.FromBase64String(privateKeyBase64);
            if (bytes.Length != 32)
            {
                return false;
            }

            // Try to import as private key
            using var key = Key.Import(KeyAgreementAlgorithm.X25519, bytes, KeyBlobFormat.RawPrivateKey);
            return true;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Generates a cryptographically secure random salt.
    /// </summary>
    /// <param name="length">Length in bytes (default 32)</param>
    /// <returns>Base64-encoded random salt</returns>
    public static string GenerateSalt(int length = 32)
    {
        var salt = new byte[length];
        RandomNumberGenerator.Fill(salt);
        return Convert.ToBase64String(salt);
    }
}
