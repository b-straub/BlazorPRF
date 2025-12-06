using System.Security.Cryptography;
using System.Text;
using BlazorPRF.Shared.Models;
using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Generators;
using BcChaCha20Poly1305 = Org.BouncyCastle.Crypto.Modes.ChaCha20Poly1305;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace BlazorPRF.Crypto;

/// <summary>
/// WASM-compatible cryptographic operations using BouncyCastle.
/// Provides X25519 + ChaCha20-Poly1305 encryption matching the TypeScript implementation.
/// </summary>
public static class CryptoOperations
{
    private const int NonceLength = 12;
    private const int KeyLength = 32;
    private const int TagLength = 16;
    private static readonly byte[] HkdfInfo = Encoding.UTF8.GetBytes("BlazorPRF-ECIES-v1");

    /// <summary>
    /// Encrypts a message using ChaCha20-Poly1305 symmetric encryption.
    /// </summary>
    public static PrfResult<SymmetricEncryptedMessage> EncryptSymmetric(string plaintext, string keyBase64)
    {
        var keyBytes = Convert.FromBase64String(keyBase64);
        try
        {
            return EncryptSymmetric(plaintext, keyBytes);
        }
        finally
        {
            Array.Clear(keyBytes, 0, keyBytes.Length);
        }
    }

    /// <summary>
    /// Encrypts a message using ChaCha20-Poly1305 symmetric encryption.
    /// Preferred overload - avoids Base64 conversion and works directly with key bytes.
    /// </summary>
    public static PrfResult<SymmetricEncryptedMessage> EncryptSymmetric(string plaintext, ReadOnlySpan<byte> key)
    {
        try
        {
            if (key.Length != KeyLength)
            {
                return PrfResult<SymmetricEncryptedMessage>.Fail(PrfErrorCode.InvalidData);
            }

            var plaintextBytes = Encoding.UTF8.GetBytes(plaintext);
            var nonce = new byte[NonceLength];
            RandomNumberGenerator.Fill(nonce);

            var ciphertext = EncryptChaCha20Poly1305(plaintextBytes, key, nonce);

            return PrfResult<SymmetricEncryptedMessage>.Ok(new SymmetricEncryptedMessage(
                Ciphertext: Convert.ToBase64String(ciphertext),
                Nonce: Convert.ToBase64String(nonce)
            ));
        }
        catch
        {
            return PrfResult<SymmetricEncryptedMessage>.Fail(PrfErrorCode.EncryptionFailed);
        }
    }

    /// <summary>
    /// Decrypts a message using ChaCha20-Poly1305 symmetric encryption.
    /// </summary>
    public static PrfResult<string> DecryptSymmetric(SymmetricEncryptedMessage encrypted, string keyBase64)
    {
        var keyBytes = Convert.FromBase64String(keyBase64);
        try
        {
            return DecryptSymmetric(encrypted, keyBytes);
        }
        finally
        {
            Array.Clear(keyBytes, 0, keyBytes.Length);
        }
    }

    /// <summary>
    /// Decrypts a message using ChaCha20-Poly1305 symmetric encryption.
    /// Preferred overload - avoids Base64 conversion and works directly with key bytes.
    /// </summary>
    public static PrfResult<string> DecryptSymmetric(SymmetricEncryptedMessage encrypted, ReadOnlySpan<byte> key)
    {
        try
        {
            if (key.Length != KeyLength)
            {
                return PrfResult<string>.Fail(PrfErrorCode.InvalidData);
            }

            var ciphertext = Convert.FromBase64String(encrypted.Ciphertext);
            var nonce = Convert.FromBase64String(encrypted.Nonce);

            if (nonce.Length != NonceLength)
            {
                return PrfResult<string>.Fail(PrfErrorCode.InvalidData);
            }

            var plaintext = DecryptChaCha20Poly1305(ciphertext, key, nonce);
            if (plaintext is null)
            {
                return PrfResult<string>.Fail(PrfErrorCode.AuthenticationTagMismatch);
            }

            return PrfResult<string>.Ok(Encoding.UTF8.GetString(plaintext));
        }
        catch
        {
            return PrfResult<string>.Fail(PrfErrorCode.DecryptionFailed);
        }
    }

    /// <summary>
    /// Encrypts a message using ECIES (X25519 + ChaCha20-Poly1305).
    /// </summary>
    public static PrfResult<EncryptedMessage> EncryptAsymmetric(string plaintext, string recipientPublicKeyBase64)
    {
        try
        {
            var recipientPublicKeyBytes = Convert.FromBase64String(recipientPublicKeyBase64);
            if (recipientPublicKeyBytes.Length != KeyLength)
            {
                return PrfResult<EncryptedMessage>.Fail(PrfErrorCode.InvalidPublicKey);
            }

            var recipientPublicKey = new X25519PublicKeyParameters(recipientPublicKeyBytes, 0);

            // Generate ephemeral key pair
            var random = new SecureRandom();
            var generator = new X25519KeyPairGenerator();
            generator.Init(new X25519KeyGenerationParameters(random));
            var ephemeralKeyPair = generator.GenerateKeyPair();

            var ephemeralPrivateKey = (X25519PrivateKeyParameters)ephemeralKeyPair.Private;
            var ephemeralPublicKey = (X25519PublicKeyParameters)ephemeralKeyPair.Public;

            // Perform X25519 key agreement
            var agreement = new X25519Agreement();
            agreement.Init(ephemeralPrivateKey);
            var sharedSecret = new byte[agreement.AgreementSize];
            agreement.CalculateAgreement(recipientPublicKey, sharedSecret, 0);

            // Get ephemeral public key bytes
            var ephemeralPublicKeyBytes = new byte[32];
            ephemeralPublicKey.Encode(ephemeralPublicKeyBytes, 0);

            // Derive encryption key using HKDF (ephemeral public key as salt)
            var encryptionKey = DeriveEncryptionKey(sharedSecret, ephemeralPublicKeyBytes);

            // Encrypt with ChaCha20-Poly1305
            var plaintextBytes = Encoding.UTF8.GetBytes(plaintext);
            var nonce = new byte[NonceLength];
            RandomNumberGenerator.Fill(nonce);

            var ciphertext = EncryptChaCha20Poly1305(plaintextBytes, encryptionKey, nonce);

            // Clear sensitive data
            Array.Clear(sharedSecret, 0, sharedSecret.Length);
            Array.Clear(encryptionKey, 0, encryptionKey.Length);

            return PrfResult<EncryptedMessage>.Ok(new EncryptedMessage(
                EphemeralPublicKey: Convert.ToBase64String(ephemeralPublicKeyBytes),
                Ciphertext: Convert.ToBase64String(ciphertext),
                Nonce: Convert.ToBase64String(nonce)
            ));
        }
        catch
        {
            return PrfResult<EncryptedMessage>.Fail(PrfErrorCode.EncryptionFailed);
        }
    }

    /// <summary>
    /// Decrypts a message using ECIES (X25519 + ChaCha20-Poly1305).
    /// </summary>
    public static PrfResult<string> DecryptAsymmetric(EncryptedMessage encrypted, string privateKeyBase64)
    {
        var privateKeyBytes = Convert.FromBase64String(privateKeyBase64);
        try
        {
            return DecryptAsymmetric(encrypted, privateKeyBytes);
        }
        finally
        {
            Array.Clear(privateKeyBytes, 0, privateKeyBytes.Length);
        }
    }

    /// <summary>
    /// Decrypts a message using ECIES (X25519 + ChaCha20-Poly1305).
    /// Preferred overload - avoids Base64 conversion and works directly with key bytes.
    /// </summary>
    public static PrfResult<string> DecryptAsymmetric(EncryptedMessage encrypted, ReadOnlySpan<byte> privateKey)
    {
        try
        {
            if (privateKey.Length != KeyLength)
            {
                return PrfResult<string>.Fail(PrfErrorCode.InvalidPrivateKey);
            }

            var ephemeralPublicKeyBytes = Convert.FromBase64String(encrypted.EphemeralPublicKey);
            if (ephemeralPublicKeyBytes.Length != KeyLength)
            {
                return PrfResult<string>.Fail(PrfErrorCode.InvalidData);
            }

            var ciphertext = Convert.FromBase64String(encrypted.Ciphertext);
            var nonce = Convert.FromBase64String(encrypted.Nonce);

            if (nonce.Length != NonceLength)
            {
                return PrfResult<string>.Fail(PrfErrorCode.InvalidData);
            }

            var privateKeyParam = new X25519PrivateKeyParameters(privateKey.ToArray(), 0);
            var ephemeralPublicKey = new X25519PublicKeyParameters(ephemeralPublicKeyBytes, 0);

            // Perform X25519 key agreement
            var agreement = new X25519Agreement();
            agreement.Init(privateKeyParam);
            var sharedSecret = new byte[agreement.AgreementSize];
            agreement.CalculateAgreement(ephemeralPublicKey, sharedSecret, 0);

            // Derive encryption key using HKDF (ephemeral public key as salt)
            var encryptionKey = DeriveEncryptionKey(sharedSecret, ephemeralPublicKeyBytes);

            // Decrypt with ChaCha20-Poly1305
            var plaintext = DecryptChaCha20Poly1305(ciphertext, encryptionKey, nonce);

            // Clear sensitive data
            Array.Clear(sharedSecret, 0, sharedSecret.Length);
            Array.Clear(encryptionKey, 0, encryptionKey.Length);

            if (plaintext is null)
            {
                return PrfResult<string>.Fail(PrfErrorCode.AuthenticationTagMismatch);
            }

            return PrfResult<string>.Ok(Encoding.UTF8.GetString(plaintext));
        }
        catch
        {
            return PrfResult<string>.Fail(PrfErrorCode.DecryptionFailed);
        }
    }

    /// <summary>
    /// Derives an encryption key from the shared secret using HKDF-SHA256.
    /// Uses ephemeral public key as salt to match TypeScript implementation.
    /// </summary>
    private static byte[] DeriveEncryptionKey(byte[] sharedSecret, byte[] ephemeralPublicKey)
    {
        // Use .NET's HKDF implementation
        return HKDF.DeriveKey(
            HashAlgorithmName.SHA256,
            sharedSecret,
            KeyLength,
            salt: ephemeralPublicKey,
            info: HkdfInfo
        );
    }

    /// <summary>
    /// Encrypts data using ChaCha20-Poly1305.
    /// </summary>
    private static byte[] EncryptChaCha20Poly1305(byte[] plaintext, ReadOnlySpan<byte> key, byte[] nonce)
    {
        var cipher = new BcChaCha20Poly1305();
        var parameters = new ParametersWithIV(new KeyParameter(key.ToArray()), nonce);
        cipher.Init(true, parameters);

        var output = new byte[cipher.GetOutputSize(plaintext.Length)];
        var len = cipher.ProcessBytes(plaintext, 0, plaintext.Length, output, 0);
        cipher.DoFinal(output, len);

        return output;
    }

    /// <summary>
    /// Decrypts data using ChaCha20-Poly1305.
    /// Returns null if authentication fails.
    /// </summary>
    private static byte[]? DecryptChaCha20Poly1305(byte[] ciphertext, ReadOnlySpan<byte> key, byte[] nonce)
    {
        try
        {
            var cipher = new BcChaCha20Poly1305();
            var parameters = new ParametersWithIV(new KeyParameter(key.ToArray()), nonce);
            cipher.Init(false, parameters);

            var output = new byte[cipher.GetOutputSize(ciphertext.Length)];
            var len = cipher.ProcessBytes(ciphertext, 0, ciphertext.Length, output, 0);
            cipher.DoFinal(output, len);

            return output;
        }
        catch (Org.BouncyCastle.Crypto.InvalidCipherTextException)
        {
            return null;
        }
    }
}
