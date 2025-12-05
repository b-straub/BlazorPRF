using System.Security.Cryptography;
using System.Text;
using BlazorPRF.Shared.Models;
using NSec.Cryptography;

namespace PseudoPRF.Services;

/// <summary>
/// Low-level cryptographic operations for X25519 + ChaCha20-Poly1305.
/// </summary>
public static class CryptoOperations
{
    private const int NonceLength = 12;
    private const int KeyLength = 32;
    private const int TagLength = 16;

    /// <summary>
    /// Encrypts a message using ChaCha20-Poly1305 symmetric encryption.
    /// </summary>
    /// <param name="plaintext">The message to encrypt</param>
    /// <param name="keyBase64">The 32-byte symmetric key (Base64)</param>
    /// <returns>The encrypted message</returns>
    public static PrfResult<SymmetricEncryptedMessage> EncryptSymmetric(string plaintext, string keyBase64)
    {
        try
        {
            var keyBytes = Convert.FromBase64String(keyBase64);
            if (keyBytes.Length != KeyLength)
            {
                return PrfResult<SymmetricEncryptedMessage>.Fail(PrfErrorCode.InvalidData);
            }

            var plaintextBytes = Encoding.UTF8.GetBytes(plaintext);
            var nonce = new byte[NonceLength];
            RandomNumberGenerator.Fill(nonce);

            using var key = Key.Import(AeadAlgorithm.ChaCha20Poly1305, keyBytes, KeyBlobFormat.RawSymmetricKey);
            var ciphertext = AeadAlgorithm.ChaCha20Poly1305.Encrypt(key, nonce, null, plaintextBytes);

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
    /// <param name="encrypted">The encrypted message</param>
    /// <param name="keyBase64">The 32-byte symmetric key (Base64)</param>
    /// <returns>The decrypted plaintext</returns>
    public static PrfResult<string> DecryptSymmetric(SymmetricEncryptedMessage encrypted, string keyBase64)
    {
        try
        {
            var keyBytes = Convert.FromBase64String(keyBase64);
            if (keyBytes.Length != KeyLength)
            {
                return PrfResult<string>.Fail(PrfErrorCode.InvalidData);
            }

            var ciphertext = Convert.FromBase64String(encrypted.Ciphertext);
            var nonce = Convert.FromBase64String(encrypted.Nonce);

            if (nonce.Length != NonceLength)
            {
                return PrfResult<string>.Fail(PrfErrorCode.InvalidData);
            }

            using var key = Key.Import(AeadAlgorithm.ChaCha20Poly1305, keyBytes, KeyBlobFormat.RawSymmetricKey);
            var plaintext = AeadAlgorithm.ChaCha20Poly1305.Decrypt(key, nonce, null, ciphertext);

            if (plaintext is null)
            {
                return PrfResult<string>.Fail(PrfErrorCode.AuthenticationTagMismatch);
            }

            return PrfResult<string>.Ok(Encoding.UTF8.GetString(plaintext));
        }
        catch (CryptographicException)
        {
            return PrfResult<string>.Fail(PrfErrorCode.AuthenticationTagMismatch);
        }
        catch
        {
            return PrfResult<string>.Fail(PrfErrorCode.DecryptionFailed);
        }
    }

    /// <summary>
    /// Encrypts a message using ECIES (X25519 + ChaCha20-Poly1305).
    /// </summary>
    /// <param name="plaintext">The message to encrypt</param>
    /// <param name="recipientPublicKeyBase64">The recipient's X25519 public key (Base64)</param>
    /// <returns>The encrypted message with ephemeral public key</returns>
    public static PrfResult<EncryptedMessage> EncryptAsymmetric(string plaintext, string recipientPublicKeyBase64)
    {
        try
        {
            var recipientPublicKeyBytes = Convert.FromBase64String(recipientPublicKeyBase64);
            if (recipientPublicKeyBytes.Length != KeyLength)
            {
                return PrfResult<EncryptedMessage>.Fail(PrfErrorCode.InvalidPublicKey);
            }

            var recipientPublicKey = PublicKey.Import(
                KeyAgreementAlgorithm.X25519,
                recipientPublicKeyBytes,
                KeyBlobFormat.RawPublicKey);

            // Generate ephemeral key pair
            using var ephemeralKey = Key.Create(KeyAgreementAlgorithm.X25519, new KeyCreationParameters
            {
                ExportPolicy = KeyExportPolicies.AllowPlaintextExport
            });

            // Perform X25519 key agreement with export permissions
            using var sharedSecret = KeyAgreementAlgorithm.X25519.Agree(
                ephemeralKey,
                recipientPublicKey,
                new SharedSecretCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextExport });
            if (sharedSecret is null)
            {
                return PrfResult<EncryptedMessage>.Fail(PrfErrorCode.KeyDerivationFailed);
            }

            var ephemeralPublicKeyBytes = ephemeralKey.PublicKey.Export(KeyBlobFormat.RawPublicKey);

            // Derive encryption key using HKDF (ephemeral public key as salt)
            var encryptionKey = DeriveEncryptionKey(sharedSecret.Export(SharedSecretBlobFormat.RawSharedSecret), ephemeralPublicKeyBytes);

            // Encrypt with ChaCha20-Poly1305
            var plaintextBytes = Encoding.UTF8.GetBytes(plaintext);
            var nonce = new byte[NonceLength];
            RandomNumberGenerator.Fill(nonce);

            using var key = Key.Import(AeadAlgorithm.ChaCha20Poly1305, encryptionKey, KeyBlobFormat.RawSymmetricKey);
            var ciphertext = AeadAlgorithm.ChaCha20Poly1305.Encrypt(key, nonce, null, plaintextBytes);

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
    /// <param name="encrypted">The encrypted message</param>
    /// <param name="privateKeyBase64">The recipient's X25519 private key (Base64)</param>
    /// <returns>The decrypted plaintext</returns>
    public static PrfResult<string> DecryptAsymmetric(EncryptedMessage encrypted, string privateKeyBase64)
    {
        try
        {
            var privateKeyBytes = Convert.FromBase64String(privateKeyBase64);
            if (privateKeyBytes.Length != KeyLength)
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

            using var privateKey = Key.Import(
                KeyAgreementAlgorithm.X25519,
                privateKeyBytes,
                KeyBlobFormat.RawPrivateKey);

            var ephemeralPublicKey = PublicKey.Import(
                KeyAgreementAlgorithm.X25519,
                ephemeralPublicKeyBytes,
                KeyBlobFormat.RawPublicKey);

            // Perform X25519 key agreement with export permissions
            using var sharedSecret = KeyAgreementAlgorithm.X25519.Agree(
                privateKey,
                ephemeralPublicKey,
                new SharedSecretCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextExport });
            if (sharedSecret is null)
            {
                return PrfResult<string>.Fail(PrfErrorCode.KeyDerivationFailed);
            }

            // Derive encryption key using HKDF (ephemeral public key as salt)
            var encryptionKey = DeriveEncryptionKey(sharedSecret.Export(SharedSecretBlobFormat.RawSharedSecret), ephemeralPublicKeyBytes);

            // Decrypt with ChaCha20-Poly1305
            using var key = Key.Import(AeadAlgorithm.ChaCha20Poly1305, encryptionKey, KeyBlobFormat.RawSymmetricKey);
            var plaintext = AeadAlgorithm.ChaCha20Poly1305.Decrypt(key, nonce, null, ciphertext);

            if (plaintext is null)
            {
                return PrfResult<string>.Fail(PrfErrorCode.AuthenticationTagMismatch);
            }

            return PrfResult<string>.Ok(Encoding.UTF8.GetString(plaintext));
        }
        catch (CryptographicException)
        {
            return PrfResult<string>.Fail(PrfErrorCode.AuthenticationTagMismatch);
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
        // Use HKDF to derive a 32-byte key
        // Salt = ephemeral public key, Info = "BlazorPRF-ECIES-v1"
        // Must match TypeScript implementation in BlazorPRF exactly
        var info = Encoding.UTF8.GetBytes("BlazorPRF-ECIES-v1");
        return HKDF.DeriveKey(HashAlgorithmName.SHA256, sharedSecret, KeyLength, salt: ephemeralPublicKey, info: info);
    }

    /// <summary>
    /// Debug version of EncryptAsymmetric that prints intermediate values.
    /// </summary>
    public static PrfResult<EncryptedMessage> EncryptAsymmetricDebug(string plaintext, string recipientPublicKeyBase64)
    {
        try
        {
            var recipientPublicKeyBytes = Convert.FromBase64String(recipientPublicKeyBase64);
            if (recipientPublicKeyBytes.Length != KeyLength)
            {
                return PrfResult<EncryptedMessage>.Fail(PrfErrorCode.InvalidPublicKey);
            }

            var recipientPublicKey = PublicKey.Import(
                KeyAgreementAlgorithm.X25519,
                recipientPublicKeyBytes,
                KeyBlobFormat.RawPublicKey);

            // Generate ephemeral key pair
            using var ephemeralKey = Key.Create(KeyAgreementAlgorithm.X25519, new KeyCreationParameters
            {
                ExportPolicy = KeyExportPolicies.AllowPlaintextExport
            });

            var ephemeralPrivateKeyBytes = ephemeralKey.Export(KeyBlobFormat.RawPrivateKey);
            var ephemeralPublicKeyBytes = ephemeralKey.PublicKey.Export(KeyBlobFormat.RawPublicKey);

            Console.Error.WriteLine($"[DEBUG] Ephemeral private key (hex): {Convert.ToHexString(ephemeralPrivateKeyBytes)}");
            Console.Error.WriteLine($"[DEBUG] Ephemeral public key (hex): {Convert.ToHexString(ephemeralPublicKeyBytes)}");

            // Perform X25519 key agreement with export permissions
            using var sharedSecret = KeyAgreementAlgorithm.X25519.Agree(
                ephemeralKey,
                recipientPublicKey,
                new SharedSecretCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextExport });
            if (sharedSecret is null)
            {
                return PrfResult<EncryptedMessage>.Fail(PrfErrorCode.KeyDerivationFailed);
            }

            var sharedSecretBytes = sharedSecret.Export(SharedSecretBlobFormat.RawSharedSecret);
            Console.Error.WriteLine($"[DEBUG] Shared secret (hex): {Convert.ToHexString(sharedSecretBytes)}");

            // Derive encryption key using HKDF (ephemeral public key as salt)
            var encryptionKey = DeriveEncryptionKey(sharedSecretBytes, ephemeralPublicKeyBytes);
            Console.Error.WriteLine($"[DEBUG] Encryption key (hex): {Convert.ToHexString(encryptionKey)}");

            // Encrypt with ChaCha20-Poly1305
            var plaintextBytes = Encoding.UTF8.GetBytes(plaintext);
            var nonce = new byte[NonceLength];
            RandomNumberGenerator.Fill(nonce);

            Console.Error.WriteLine($"[DEBUG] Nonce (hex): {Convert.ToHexString(nonce)}");
            Console.Error.WriteLine($"[DEBUG] Plaintext (hex): {Convert.ToHexString(plaintextBytes)}");

            using var key = Key.Import(AeadAlgorithm.ChaCha20Poly1305, encryptionKey, KeyBlobFormat.RawSymmetricKey);
            var ciphertext = AeadAlgorithm.ChaCha20Poly1305.Encrypt(key, nonce, null, plaintextBytes);

            Console.Error.WriteLine($"[DEBUG] Ciphertext (hex): {Convert.ToHexString(ciphertext)}");

            return PrfResult<EncryptedMessage>.Ok(new EncryptedMessage(
                EphemeralPublicKey: Convert.ToBase64String(ephemeralPublicKeyBytes),
                Ciphertext: Convert.ToBase64String(ciphertext),
                Nonce: Convert.ToBase64String(nonce)
            ));
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[DEBUG] Exception: {ex}");
            return PrfResult<EncryptedMessage>.Fail(PrfErrorCode.EncryptionFailed);
        }
    }

    /// <summary>
    /// Debug version of DecryptAsymmetric that prints intermediate values.
    /// </summary>
    public static PrfResult<string> DecryptAsymmetricDebug(EncryptedMessage encrypted, string privateKeyBase64)
    {
        try
        {
            var privateKeyBytes = Convert.FromBase64String(privateKeyBase64);
            if (privateKeyBytes.Length != KeyLength)
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

            Console.Error.WriteLine($"[DEBUG] Ciphertext (hex): {Convert.ToHexString(ciphertext)}");
            Console.Error.WriteLine($"[DEBUG] Nonce (hex): {Convert.ToHexString(nonce)}");

            using var privateKey = Key.Import(
                KeyAgreementAlgorithm.X25519,
                privateKeyBytes,
                KeyBlobFormat.RawPrivateKey);

            var ephemeralPublicKey = PublicKey.Import(
                KeyAgreementAlgorithm.X25519,
                ephemeralPublicKeyBytes,
                KeyBlobFormat.RawPublicKey);

            // Perform X25519 key agreement with export permissions
            using var sharedSecret = KeyAgreementAlgorithm.X25519.Agree(
                privateKey,
                ephemeralPublicKey,
                new SharedSecretCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextExport });
            if (sharedSecret is null)
            {
                return PrfResult<string>.Fail(PrfErrorCode.KeyDerivationFailed);
            }

            var sharedSecretBytes = sharedSecret.Export(SharedSecretBlobFormat.RawSharedSecret);
            Console.Error.WriteLine($"[DEBUG] Shared secret (hex): {Convert.ToHexString(sharedSecretBytes)}");

            // Derive encryption key using HKDF (ephemeral public key as salt)
            var encryptionKey = DeriveEncryptionKey(sharedSecretBytes, ephemeralPublicKeyBytes);
            Console.Error.WriteLine($"[DEBUG] Encryption key (hex): {Convert.ToHexString(encryptionKey)}");

            // Decrypt with ChaCha20-Poly1305
            using var key = Key.Import(AeadAlgorithm.ChaCha20Poly1305, encryptionKey, KeyBlobFormat.RawSymmetricKey);
            var plaintext = AeadAlgorithm.ChaCha20Poly1305.Decrypt(key, nonce, null, ciphertext);

            if (plaintext is null)
            {
                Console.Error.WriteLine("[DEBUG] Decryption returned null (tag mismatch)");
                return PrfResult<string>.Fail(PrfErrorCode.AuthenticationTagMismatch);
            }

            Console.Error.WriteLine($"[DEBUG] Plaintext (hex): {Convert.ToHexString(plaintext)}");
            return PrfResult<string>.Ok(Encoding.UTF8.GetString(plaintext));
        }
        catch (CryptographicException ex)
        {
            Console.Error.WriteLine($"[DEBUG] CryptographicException: {ex.Message}");
            return PrfResult<string>.Fail(PrfErrorCode.AuthenticationTagMismatch);
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[DEBUG] Exception: {ex}");
            return PrfResult<string>.Fail(PrfErrorCode.DecryptionFailed);
        }
    }
}
