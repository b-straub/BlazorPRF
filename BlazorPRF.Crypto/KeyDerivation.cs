using BlazorPRF.Shared.Models;
using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace BlazorPRF.Crypto;

/// <summary>
/// Key derivation utilities for PRF-based key generation.
/// </summary>
public static class KeyDerivation
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
}
