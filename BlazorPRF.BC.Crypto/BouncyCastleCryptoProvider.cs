using System.Text;
using BlazorPRF.Shared.Crypto.Abstractions;
using BlazorPRF.Shared.Crypto.Models;
using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace BlazorPRF.BC.Crypto;

/// <summary>
/// BouncyCastle-based crypto provider.
/// Supports all algorithms including ChaCha20-Poly1305.
/// </summary>
public sealed class BouncyCastleCryptoProvider : ICryptoProvider
{
    private const int NonceLength = 12;
    private const int KeyLength = 32;

    // HKDF info strings must match Noble.js for interoperability
    private static readonly byte[] HkdfInfoAesGcm = "ecies-aes-gcm"u8.ToArray();
    private static readonly byte[] HkdfInfoChaCha = "ecies-xchacha20poly1305"u8.ToArray();

    private static readonly IReadOnlyList<EncryptionAlgorithm> Algorithms =
        [EncryptionAlgorithm.CHA_CHA20_POLY1305, EncryptionAlgorithm.AES_GCM];

    public string ProviderName => "BouncyCastle";

    public IReadOnlyList<EncryptionAlgorithm> SupportedAlgorithms => Algorithms;

    public bool IsAlgorithmSupported(EncryptionAlgorithm algorithm) =>
        algorithm is EncryptionAlgorithm.CHA_CHA20_POLY1305 or EncryptionAlgorithm.AES_GCM;

    // ============================================================
    // SYMMETRIC ENCRYPTION
    // ============================================================

    public ValueTask<PrfResult<SymmetricEncryptedMessage>> EncryptSymmetricAsync(
        string plaintext,
        ReadOnlyMemory<byte> key,
        EncryptionAlgorithm algorithm = EncryptionAlgorithm.AES_GCM)
    {
        try
        {
            if (key.Length != KeyLength)
            {
                return ValueTask.FromResult(PrfResult<SymmetricEncryptedMessage>.Fail(PrfErrorCode.INVALID_DATA));
            }

            var plaintextBytes = Encoding.UTF8.GetBytes(plaintext);
            var nonce = new byte[NonceLength];
            new SecureRandom().NextBytes(nonce);

            var ciphertext = algorithm switch
            {
                EncryptionAlgorithm.CHA_CHA20_POLY1305 => CryptoOperations.EncryptChaCha20Poly1305(plaintextBytes, key.Span, nonce),
                EncryptionAlgorithm.AES_GCM => CryptoOperations.EncryptAesGcm(plaintextBytes, key.Span, nonce),
                _ => throw new NotSupportedException($"Algorithm {algorithm} not supported")
            };

            return ValueTask.FromResult(PrfResult<SymmetricEncryptedMessage>.Ok(new SymmetricEncryptedMessage(
                Ciphertext: Convert.ToBase64String(ciphertext),
                Nonce: Convert.ToBase64String(nonce)
            )));
        }
        catch (NotSupportedException)
        {
            throw;
        }
        catch
        {
            return ValueTask.FromResult(PrfResult<SymmetricEncryptedMessage>.Fail(PrfErrorCode.ENCRYPTION_FAILED));
        }
    }

    public ValueTask<PrfResult<string>> DecryptSymmetricAsync(
        SymmetricEncryptedMessage encrypted,
        ReadOnlyMemory<byte> key,
        EncryptionAlgorithm algorithm = EncryptionAlgorithm.AES_GCM)
    {
        try
        {
            if (key.Length != KeyLength)
            {
                return ValueTask.FromResult(PrfResult<string>.Fail(PrfErrorCode.INVALID_DATA));
            }

            var ciphertext = Convert.FromBase64String(encrypted.Ciphertext);
            var nonce = Convert.FromBase64String(encrypted.Nonce);

            if (nonce.Length != NonceLength)
            {
                return ValueTask.FromResult(PrfResult<string>.Fail(PrfErrorCode.INVALID_DATA));
            }

            var plaintext = algorithm switch
            {
                EncryptionAlgorithm.CHA_CHA20_POLY1305 => CryptoOperations.DecryptChaCha20Poly1305(ciphertext, key.Span, nonce),
                EncryptionAlgorithm.AES_GCM => CryptoOperations.DecryptAesGcm(ciphertext, key.Span, nonce),
                _ => throw new NotSupportedException($"Algorithm {algorithm} not supported")
            };

            if (plaintext is null)
            {
                return ValueTask.FromResult(PrfResult<string>.Fail(PrfErrorCode.AUTHENTICATION_TAG_MISMATCH));
            }

            return ValueTask.FromResult(PrfResult<string>.Ok(Encoding.UTF8.GetString(plaintext)));
        }
        catch (NotSupportedException)
        {
            throw;
        }
        catch
        {
            return ValueTask.FromResult(PrfResult<string>.Fail(PrfErrorCode.DECRYPTION_FAILED));
        }
    }

    // ============================================================
    // ASYMMETRIC ENCRYPTION (ECIES)
    // ============================================================

    public ValueTask<PrfResult<EncryptedMessage>> EncryptAsymmetricAsync(
        string plaintext,
        string recipientPublicKeyBase64,
        EncryptionAlgorithm algorithm = EncryptionAlgorithm.AES_GCM)
    {
        try
        {
            var recipientPublicKeyBytes = Convert.FromBase64String(recipientPublicKeyBase64);
            if (recipientPublicKeyBytes.Length != KeyLength)
            {
                return ValueTask.FromResult(PrfResult<EncryptedMessage>.Fail(PrfErrorCode.INVALID_PUBLIC_KEY));
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

            // Derive encryption key using HKDF (null salt = 32 zeros to match Noble.js)
            var hkdfInfo = algorithm == EncryptionAlgorithm.CHA_CHA20_POLY1305 ? HkdfInfoChaCha : HkdfInfoAesGcm;
            var encryptionKey = KeyGenerator.HkdfDeriveKey(sharedSecret, null, hkdfInfo, KeyLength);

            // Encrypt
            var plaintextBytes = Encoding.UTF8.GetBytes(plaintext);
            var nonce = new byte[NonceLength];
            random.NextBytes(nonce);

            var ciphertext = algorithm switch
            {
                EncryptionAlgorithm.CHA_CHA20_POLY1305 => CryptoOperations.EncryptChaCha20Poly1305(plaintextBytes, encryptionKey, nonce),
                EncryptionAlgorithm.AES_GCM => CryptoOperations.EncryptAesGcm(plaintextBytes, encryptionKey, nonce),
                _ => throw new NotSupportedException($"Algorithm {algorithm} not supported")
            };

            // Clear sensitive data
            Array.Clear(sharedSecret, 0, sharedSecret.Length);
            Array.Clear(encryptionKey, 0, encryptionKey.Length);

            return ValueTask.FromResult(PrfResult<EncryptedMessage>.Ok(new EncryptedMessage(
                EphemeralPublicKey: Convert.ToBase64String(ephemeralPublicKeyBytes),
                Ciphertext: Convert.ToBase64String(ciphertext),
                Nonce: Convert.ToBase64String(nonce),
                Algorithm: algorithm
            )));
        }
        catch (NotSupportedException)
        {
            throw;
        }
        catch
        {
            return ValueTask.FromResult(PrfResult<EncryptedMessage>.Fail(PrfErrorCode.ENCRYPTION_FAILED));
        }
    }

    public ValueTask<PrfResult<string>> DecryptAsymmetricAsync(
        EncryptedMessage encrypted,
        ReadOnlyMemory<byte> privateKey,
        EncryptionAlgorithm algorithm = EncryptionAlgorithm.AES_GCM)
    {
        try
        {
            if (privateKey.Length != KeyLength)
            {
                return ValueTask.FromResult(PrfResult<string>.Fail(PrfErrorCode.INVALID_PRIVATE_KEY));
            }

            var ephemeralPublicKeyBytes = Convert.FromBase64String(encrypted.EphemeralPublicKey);
            if (ephemeralPublicKeyBytes.Length != KeyLength)
            {
                return ValueTask.FromResult(PrfResult<string>.Fail(PrfErrorCode.INVALID_DATA));
            }

            var ciphertext = Convert.FromBase64String(encrypted.Ciphertext);
            var nonce = Convert.FromBase64String(encrypted.Nonce);

            if (nonce.Length != NonceLength)
            {
                return ValueTask.FromResult(PrfResult<string>.Fail(PrfErrorCode.INVALID_DATA));
            }

            var privateKeyParam = new X25519PrivateKeyParameters(privateKey.ToArray(), 0);
            var ephemeralPublicKey = new X25519PublicKeyParameters(ephemeralPublicKeyBytes, 0);

            // Perform X25519 key agreement
            var agreement = new X25519Agreement();
            agreement.Init(privateKeyParam);
            var sharedSecret = new byte[agreement.AgreementSize];
            agreement.CalculateAgreement(ephemeralPublicKey, sharedSecret, 0);

            // Use algorithm from message if available, otherwise use parameter
            var effectiveAlgorithm = encrypted.Algorithm ?? algorithm;

            // Derive encryption key using HKDF (null salt = 32 zeros to match Noble.js)
            var hkdfInfo = effectiveAlgorithm == EncryptionAlgorithm.CHA_CHA20_POLY1305 ? HkdfInfoChaCha : HkdfInfoAesGcm;
            var encryptionKey = KeyGenerator.HkdfDeriveKey(sharedSecret, null, hkdfInfo, KeyLength);

            // Decrypt
            var plaintext = effectiveAlgorithm switch
            {
                EncryptionAlgorithm.CHA_CHA20_POLY1305 => CryptoOperations.DecryptChaCha20Poly1305(ciphertext, encryptionKey, nonce),
                EncryptionAlgorithm.AES_GCM => CryptoOperations.DecryptAesGcm(ciphertext, encryptionKey, nonce),
                _ => throw new NotSupportedException($"Algorithm {effectiveAlgorithm} not supported")
            };

            // Clear sensitive data
            Array.Clear(sharedSecret, 0, sharedSecret.Length);
            Array.Clear(encryptionKey, 0, encryptionKey.Length);

            if (plaintext is null)
            {
                return ValueTask.FromResult(PrfResult<string>.Fail(PrfErrorCode.AUTHENTICATION_TAG_MISMATCH));
            }

            return ValueTask.FromResult(PrfResult<string>.Ok(Encoding.UTF8.GetString(plaintext)));
        }
        catch (NotSupportedException)
        {
            throw;
        }
        catch
        {
            return ValueTask.FromResult(PrfResult<string>.Fail(PrfErrorCode.DECRYPTION_FAILED));
        }
    }

    // ============================================================
    // ED25519 DIGITAL SIGNATURES
    // ============================================================

    public ValueTask<PrfResult<string>> SignAsync(string message, ReadOnlyMemory<byte> privateKey)
    {
        var result = CryptoOperations.Sign(message, privateKey.Span);
        return ValueTask.FromResult(result);
    }

    public ValueTask<bool> VerifyAsync(string message, string signatureBase64, string publicKeyBase64)
    {
        var result = CryptoOperations.Verify(message, signatureBase64, publicKeyBase64);
        return ValueTask.FromResult(result);
    }

    // ============================================================
    // KEY GENERATION
    // ============================================================

    public ValueTask<KeyPair> DeriveX25519KeyPairAsync(ReadOnlyMemory<byte> prfSeed)
    {
        var keyPair = KeyGenerator.DeriveKeypairFromPrf(prfSeed.ToArray());
        return ValueTask.FromResult(keyPair);
    }

    public ValueTask<KeyPair> DeriveEd25519KeyPairAsync(ReadOnlyMemory<byte> prfSeed)
    {
        var keyPair = KeyGenerator.DeriveEd25519KeyPair(prfSeed.ToArray());
        return ValueTask.FromResult(keyPair);
    }

    public ValueTask<DualKeyPairFull> DeriveDualKeyPairAsync(ReadOnlyMemory<byte> prfSeed)
    {
        var dualKeyPair = KeyGenerator.DeriveDualKeyPair(prfSeed.ToArray());
        return ValueTask.FromResult(dualKeyPair);
    }

    public ValueTask<string> GenerateSaltAsync(int length = 32)
    {
        var salt = KeyGenerator.GenerateSalt(length);
        return ValueTask.FromResult(salt);
    }
}
