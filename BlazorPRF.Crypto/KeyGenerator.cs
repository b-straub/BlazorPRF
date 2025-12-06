using BlazorPRF.Shared.Models;
using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace BlazorPRF.Crypto;

/// <summary>
/// Key derivation utilities for PRF-based key generation.
/// </summary>
public static class KeyGenerator
{
    /// <summary>
    /// Derives an X25519 keypair from a 32-byte PRF output.
    /// The PRF output is used directly as the private key.
    /// </summary>
    /// <param name="prfOutputBase64">32-byte PRF output (Base64)</param>
    /// <returns>KeyPair with private and public keys</returns>
    public static KeyPair DeriveKeypairFromPrf(string prfOutputBase64)
    {
        var prfOutput = Convert.FromBase64String(prfOutputBase64);
        if (prfOutput.Length != 32)
        {
            throw new ArgumentException("PRF output must be 32 bytes", nameof(prfOutputBase64));
        }

        return DeriveKeypairFromPrf(prfOutput);
    }

    /// <summary>
    /// Derives an X25519 keypair from a 32-byte PRF output.
    /// The PRF output is used directly as the private key.
    /// </summary>
    /// <param name="prfOutput">32-byte PRF output</param>
    /// <returns>KeyPair with private and public keys</returns>
    public static KeyPair DeriveKeypairFromPrf(byte[] prfOutput)
    {
        if (prfOutput.Length != 32)
        {
            throw new ArgumentException("PRF output must be 32 bytes", nameof(prfOutput));
        }

        // Use PRF output directly as private key
        // X25519 will apply clamping internally
        var privateKeyParams = new X25519PrivateKeyParameters(prfOutput, 0);
        var publicKeyParams = privateKeyParams.GeneratePublicKey();

        var privateKeyBytes = new byte[32];
        var publicKeyBytes = new byte[32];

        privateKeyParams.Encode(privateKeyBytes, 0);
        publicKeyParams.Encode(publicKeyBytes, 0);

        return new KeyPair(
            Convert.ToBase64String(privateKeyBytes),
            Convert.ToBase64String(publicKeyBytes)
        );
    }

    /// <summary>
    /// Generates a random X25519 keypair.
    /// </summary>
    public static KeyPair GenerateKeyPair()
    {
        var random = new SecureRandom();
        var generator = new X25519KeyPairGenerator();
        generator.Init(new X25519KeyGenerationParameters(random));

        var keyPair = generator.GenerateKeyPair();
        var privateKey = (X25519PrivateKeyParameters)keyPair.Private;
        var publicKey = (X25519PublicKeyParameters)keyPair.Public;

        var privateKeyBytes = new byte[32];
        var publicKeyBytes = new byte[32];

        privateKey.Encode(privateKeyBytes, 0);
        publicKey.Encode(publicKeyBytes, 0);

        return new KeyPair(
            Convert.ToBase64String(privateKeyBytes),
            Convert.ToBase64String(publicKeyBytes)
        );
    }

    /// <summary>
    /// Gets the public key from a private key.
    /// </summary>
    public static string GetPublicKey(string privateKeyBase64)
    {
        var privateKeyBytes = Convert.FromBase64String(privateKeyBase64);
        if (privateKeyBytes.Length != 32)
        {
            throw new ArgumentException("Private key must be 32 bytes", nameof(privateKeyBase64));
        }

        var privateKey = new X25519PrivateKeyParameters(privateKeyBytes, 0);
        var publicKey = privateKey.GeneratePublicKey();

        var publicKeyBytes = new byte[32];
        publicKey.Encode(publicKeyBytes, 0);

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
            _ = new X25519PublicKeyParameters(bytes, 0);
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
            _ = new X25519PrivateKeyParameters(bytes, 0);
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
        var random = new SecureRandom();
        random.NextBytes(salt);
        return Convert.ToBase64String(salt);
    }
}
