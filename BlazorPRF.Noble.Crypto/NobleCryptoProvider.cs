using System.Runtime.Versioning;
using System.Text;
using System.Text.Json;
using BlazorPRF.Noble.Crypto.Interop;
using BlazorPRF.Shared.Crypto.Abstractions;
using BlazorPRF.Shared.Crypto.Models;

namespace BlazorPRF.Noble.Crypto;

/// <summary>
/// Crypto provider using Noble.js (X25519, Ed25519, ChaCha20-Poly1305) + SubtleCrypto (AES-GCM).
/// This provider runs cryptographic operations in JavaScript via JSImport.
/// </summary>
[SupportedOSPlatform("browser")]
public sealed class NobleCryptoProvider : ICryptoProvider
{
    private static readonly IReadOnlyList<EncryptionAlgorithm> Algorithms =
    [
        EncryptionAlgorithm.ChaCha20Poly1305,
        EncryptionAlgorithm.AesGcm
    ];

    /// <inheritdoc />
    public string ProviderName => "Noble.js + SubtleCrypto";

    /// <inheritdoc />
    public IReadOnlyList<EncryptionAlgorithm> SupportedAlgorithms => Algorithms;

    /// <inheritdoc />
    public bool IsAlgorithmSupported(EncryptionAlgorithm algorithm) =>
        algorithm is EncryptionAlgorithm.ChaCha20Poly1305 or EncryptionAlgorithm.AesGcm;

    // ============================================================
    // SYMMETRIC ENCRYPTION
    // ============================================================

    /// <inheritdoc />
    public async ValueTask<PrfResult<SymmetricEncryptedMessage>> EncryptSymmetricAsync(
        string plaintext,
        ReadOnlyMemory<byte> key,
        EncryptionAlgorithm algorithm = EncryptionAlgorithm.AesGcm)
    {
        await NobleInterop.EnsureInitializedAsync();

        var plaintextBase64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(plaintext));
        var keyBase64 = Convert.ToBase64String(key.Span);

        string resultJson;

        if (algorithm == EncryptionAlgorithm.ChaCha20Poly1305)
        {
            resultJson = NobleInterop.EncryptChaCha(plaintextBase64, keyBase64);
        }
        else
        {
            resultJson = await NobleInterop.EncryptAesGcmAsync(plaintextBase64, keyBase64);
        }

        return ParseSymmetricEncryptResult(resultJson);
    }

    /// <inheritdoc />
    public async ValueTask<PrfResult<string>> DecryptSymmetricAsync(
        SymmetricEncryptedMessage encrypted,
        ReadOnlyMemory<byte> key,
        EncryptionAlgorithm algorithm = EncryptionAlgorithm.AesGcm)
    {
        await NobleInterop.EnsureInitializedAsync();

        var keyBase64 = Convert.ToBase64String(key.Span);

        string resultJson;

        if (algorithm == EncryptionAlgorithm.ChaCha20Poly1305)
        {
            resultJson = NobleInterop.DecryptChaCha(encrypted.Ciphertext, encrypted.Nonce, keyBase64);
        }
        else
        {
            resultJson = await NobleInterop.DecryptAesGcmAsync(encrypted.Ciphertext, encrypted.Nonce, keyBase64);
        }

        return ParseDecryptResult(resultJson);
    }

    // ============================================================
    // ASYMMETRIC ENCRYPTION (ECIES)
    // ============================================================

    /// <inheritdoc />
    public async ValueTask<PrfResult<EncryptedMessage>> EncryptAsymmetricAsync(
        string plaintext,
        string recipientPublicKeyBase64,
        EncryptionAlgorithm algorithm = EncryptionAlgorithm.AesGcm)
    {
        await NobleInterop.EnsureInitializedAsync();

        var plaintextBase64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(plaintext));

        string resultJson;

        if (algorithm == EncryptionAlgorithm.ChaCha20Poly1305)
        {
            resultJson = NobleInterop.EncryptAsymmetricChaCha(plaintextBase64, recipientPublicKeyBase64);
        }
        else
        {
            resultJson = await NobleInterop.EncryptAsymmetricAesGcmAsync(plaintextBase64, recipientPublicKeyBase64);
        }

        return ParseAsymmetricEncryptResult(resultJson);
    }

    /// <inheritdoc />
    public async ValueTask<PrfResult<string>> DecryptAsymmetricAsync(
        EncryptedMessage encrypted,
        ReadOnlyMemory<byte> privateKey,
        EncryptionAlgorithm algorithm = EncryptionAlgorithm.AesGcm)
    {
        await NobleInterop.EnsureInitializedAsync();

        var privateKeyBase64 = Convert.ToBase64String(privateKey.Span);

        string resultJson;

        if (algorithm == EncryptionAlgorithm.ChaCha20Poly1305)
        {
            resultJson = NobleInterop.DecryptAsymmetricChaCha(
                encrypted.EphemeralPublicKey,
                encrypted.Ciphertext,
                encrypted.Nonce,
                privateKeyBase64);
        }
        else
        {
            resultJson = await NobleInterop.DecryptAsymmetricAesGcmAsync(
                encrypted.EphemeralPublicKey,
                encrypted.Ciphertext,
                encrypted.Nonce,
                privateKeyBase64);
        }

        return ParseDecryptResult(resultJson);
    }

    // ============================================================
    // ED25519 DIGITAL SIGNATURES
    // ============================================================

    /// <inheritdoc />
    public async ValueTask<PrfResult<string>> SignAsync(string message, ReadOnlyMemory<byte> privateKey)
    {
        await NobleInterop.EnsureInitializedAsync();

        var messageBase64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(message));
        var privateKeyBase64 = Convert.ToBase64String(privateKey.Span);

        var resultJson = NobleInterop.Ed25519Sign(messageBase64, privateKeyBase64);

        using var doc = JsonDocument.Parse(resultJson);
        var root = doc.RootElement;

        if (root.GetProperty("success").GetBoolean())
        {
            return PrfResult<string>.Ok(root.GetProperty("signatureBase64").GetString()!);
        }

        return PrfResult<string>.Fail(PrfErrorCode.SigningFailed);
    }

    /// <inheritdoc />
    public async ValueTask<bool> VerifyAsync(string message, string signatureBase64, string publicKeyBase64)
    {
        await NobleInterop.EnsureInitializedAsync();

        var messageBase64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(message));

        return NobleInterop.Ed25519Verify(messageBase64, signatureBase64, publicKeyBase64);
    }

    // ============================================================
    // KEY GENERATION
    // ============================================================

    /// <inheritdoc />
    public async ValueTask<KeyPair> DeriveX25519KeyPairAsync(ReadOnlyMemory<byte> prfSeed)
    {
        await NobleInterop.EnsureInitializedAsync();

        var seedBase64 = Convert.ToBase64String(prfSeed.Span);
        var resultJson = NobleInterop.DeriveX25519KeyPair(seedBase64);

        return ParseKeyPairResult(resultJson);
    }

    /// <inheritdoc />
    public async ValueTask<KeyPair> DeriveEd25519KeyPairAsync(ReadOnlyMemory<byte> prfSeed)
    {
        await NobleInterop.EnsureInitializedAsync();

        var seedBase64 = Convert.ToBase64String(prfSeed.Span);
        var resultJson = NobleInterop.DeriveEd25519KeyPair(seedBase64);

        return ParseKeyPairResult(resultJson);
    }

    /// <inheritdoc />
    public async ValueTask<DualKeyPairFull> DeriveDualKeyPairAsync(ReadOnlyMemory<byte> prfSeed)
    {
        await NobleInterop.EnsureInitializedAsync();

        var seedBase64 = Convert.ToBase64String(prfSeed.Span);
        var resultJson = NobleInterop.DeriveDualKeyPair(seedBase64);

        using var doc = JsonDocument.Parse(resultJson);
        var root = doc.RootElement;

        if (!root.GetProperty("success").GetBoolean())
        {
            throw new InvalidOperationException(
                root.TryGetProperty("error", out var errorProp) ? errorProp.GetString() : "Key derivation failed");
        }

        return new DualKeyPairFull(
            root.GetProperty("x25519PrivateKeyBase64").GetString()!,
            root.GetProperty("x25519PublicKeyBase64").GetString()!,
            root.GetProperty("ed25519PrivateKeyBase64").GetString()!,
            root.GetProperty("ed25519PublicKeyBase64").GetString()!
        );
    }

    /// <inheritdoc />
    public async ValueTask<string> GenerateSaltAsync(int length = 32)
    {
        await NobleInterop.EnsureInitializedAsync();

        return NobleInterop.GenerateRandomBytes(length);
    }

    // ============================================================
    // KEY-ID BASED OPERATIONS (Keys stay in JS, C# only uses keyId)
    // ============================================================

    /// <inheritdoc />
    public bool SupportsKeyIdOperations => true;

    /// <inheritdoc />
    public async ValueTask<PrfResult<DualKeyPair>> StoreKeysAsync(string keyId, ReadOnlyMemory<byte> prfSeed, int? ttlMs)
    {
        await NobleInterop.EnsureInitializedAsync();

        var seedBase64 = Convert.ToBase64String(prfSeed.Span);
        var resultJson = await NobleInterop.StoreKeysAsync(keyId, seedBase64, ttlMs);

        return ParseDualKeyPairResult(resultJson);
    }

    /// <inheritdoc />
    public async ValueTask<PrfResult<DualKeyPair>> GetPublicKeysAsync(string keyId)
    {
        await NobleInterop.EnsureInitializedAsync();

        var resultJson = NobleInterop.GetPublicKeys(keyId);
        return ParseDualKeyPairResult(resultJson);
    }

    /// <inheritdoc />
    public bool HasCachedKey(string keyId)
    {
        // Note: This is synchronous because it's a simple lookup
        // EnsureInitializedAsync should have been called before this
        return NobleInterop.HasKey(keyId);
    }

    /// <inheritdoc />
    public void RemoveCachedKey(string keyId)
    {
        NobleInterop.RemoveKeys(keyId);
    }

    /// <inheritdoc />
    public async ValueTask<PrfResult<string>> SignWithKeyIdAsync(string message, string keyId)
    {
        await NobleInterop.EnsureInitializedAsync();

        var messageBase64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(message));
        var resultJson = NobleInterop.SignWithCachedKey(keyId, messageBase64);

        using var doc = JsonDocument.Parse(resultJson);
        var root = doc.RootElement;

        if (root.GetProperty("success").GetBoolean())
        {
            return PrfResult<string>.Ok(root.GetProperty("signatureBase64").GetString()!);
        }

        return PrfResult<string>.Fail(PrfErrorCode.SigningFailed);
    }

    /// <inheritdoc />
    public async ValueTask<PrfResult<SymmetricEncryptedMessage>> EncryptSymmetricWithKeyIdAsync(
        string plaintext,
        string keyId,
        EncryptionAlgorithm algorithm = EncryptionAlgorithm.AesGcm)
    {
        await NobleInterop.EnsureInitializedAsync();

        var plaintextBase64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(plaintext));

        string resultJson;

        if (algorithm == EncryptionAlgorithm.ChaCha20Poly1305)
        {
            resultJson = NobleInterop.EncryptSymmetricCachedChaCha(keyId, plaintextBase64);
        }
        else
        {
            resultJson = await NobleInterop.EncryptSymmetricCachedAesGcmAsync(keyId, plaintextBase64);
        }

        return ParseSymmetricEncryptResult(resultJson);
    }

    /// <inheritdoc />
    public async ValueTask<PrfResult<string>> DecryptSymmetricWithKeyIdAsync(
        SymmetricEncryptedMessage encrypted,
        string keyId,
        EncryptionAlgorithm algorithm = EncryptionAlgorithm.AesGcm)
    {
        await NobleInterop.EnsureInitializedAsync();

        string resultJson;

        if (algorithm == EncryptionAlgorithm.ChaCha20Poly1305)
        {
            resultJson = NobleInterop.DecryptSymmetricCachedChaCha(keyId, encrypted.Ciphertext, encrypted.Nonce);
        }
        else
        {
            resultJson = await NobleInterop.DecryptSymmetricCachedAesGcmAsync(keyId, encrypted.Ciphertext, encrypted.Nonce);
        }

        return ParseDecryptResult(resultJson);
    }

    /// <inheritdoc />
    public async ValueTask<PrfResult<string>> DecryptAsymmetricWithKeyIdAsync(
        EncryptedMessage encrypted,
        string keyId,
        EncryptionAlgorithm algorithm = EncryptionAlgorithm.AesGcm)
    {
        await NobleInterop.EnsureInitializedAsync();

        string resultJson;

        if (algorithm == EncryptionAlgorithm.ChaCha20Poly1305)
        {
            resultJson = NobleInterop.DecryptAsymmetricCachedChaCha(
                keyId,
                encrypted.EphemeralPublicKey,
                encrypted.Ciphertext,
                encrypted.Nonce);
        }
        else
        {
            resultJson = await NobleInterop.DecryptAsymmetricCachedAesGcmAsync(
                keyId,
                encrypted.EphemeralPublicKey,
                encrypted.Ciphertext,
                encrypted.Nonce);
        }

        return ParseDecryptResult(resultJson);
    }

    // ============================================================
    // ADDITIONAL METHODS (not in ICryptoProvider)
    // ============================================================

    /// <summary>
    /// Check if the Noble.js crypto provider is fully functional.
    /// </summary>
    public async ValueTask<bool> IsSupportedAsync()
    {
        await NobleInterop.EnsureInitializedAsync();
        return NobleInterop.IsSupported();
    }

    /// <summary>
    /// Generate a new X25519 keypair.
    /// </summary>
    public async ValueTask<KeyPair> GenerateX25519KeyPairAsync()
    {
        await NobleInterop.EnsureInitializedAsync();
        var resultJson = NobleInterop.GenerateX25519KeyPair();
        return ParseKeyPairResult(resultJson);
    }

    /// <summary>
    /// Generate a new Ed25519 keypair.
    /// </summary>
    public async ValueTask<KeyPair> GenerateEd25519KeyPairAsync()
    {
        await NobleInterop.EnsureInitializedAsync();
        var resultJson = NobleInterop.GenerateEd25519KeyPair();
        return ParseKeyPairResult(resultJson);
    }

    /// <summary>
    /// Get the X25519 public key from a private key.
    /// </summary>
    public async ValueTask<string> GetX25519PublicKeyAsync(string privateKeyBase64)
    {
        await NobleInterop.EnsureInitializedAsync();
        return NobleInterop.GetX25519PublicKey(privateKeyBase64);
    }

    /// <summary>
    /// Get the Ed25519 public key from a private key.
    /// </summary>
    public async ValueTask<string> GetEd25519PublicKeyAsync(string privateKeyBase64)
    {
        await NobleInterop.EnsureInitializedAsync();
        return NobleInterop.GetEd25519PublicKey(privateKeyBase64);
    }

    // ============================================================
    // PARSING HELPERS
    // ============================================================

    private static PrfResult<SymmetricEncryptedMessage> ParseSymmetricEncryptResult(string resultJson)
    {
        using var doc = JsonDocument.Parse(resultJson);
        var root = doc.RootElement;

        if (root.GetProperty("success").GetBoolean())
        {
            var message = new SymmetricEncryptedMessage(
                root.GetProperty("ciphertextBase64").GetString()!,
                root.GetProperty("nonceBase64").GetString()!
            );
            return PrfResult<SymmetricEncryptedMessage>.Ok(message);
        }

        return PrfResult<SymmetricEncryptedMessage>.Fail(PrfErrorCode.EncryptionFailed);
    }

    private static PrfResult<EncryptedMessage> ParseAsymmetricEncryptResult(string resultJson)
    {
        using var doc = JsonDocument.Parse(resultJson);
        var root = doc.RootElement;

        if (root.GetProperty("success").GetBoolean())
        {
            var message = new EncryptedMessage(
                root.GetProperty("ephemeralPublicKeyBase64").GetString()!,
                root.GetProperty("ciphertextBase64").GetString()!,
                root.GetProperty("nonceBase64").GetString()!
            );
            return PrfResult<EncryptedMessage>.Ok(message);
        }

        return PrfResult<EncryptedMessage>.Fail(PrfErrorCode.EncryptionFailed);
    }

    private static PrfResult<string> ParseDecryptResult(string resultJson)
    {
        using var doc = JsonDocument.Parse(resultJson);
        var root = doc.RootElement;

        if (root.GetProperty("success").GetBoolean())
        {
            var plaintextBase64 = root.GetProperty("plaintextBase64").GetString()!;
            var plaintext = Encoding.UTF8.GetString(Convert.FromBase64String(plaintextBase64));
            return PrfResult<string>.Ok(plaintext);
        }

        // Check for authentication tag mismatch
        var error = root.TryGetProperty("error", out var errorProp) ? errorProp.GetString() : null;
        if (error is not null && error.Contains("tag", StringComparison.OrdinalIgnoreCase))
        {
            return PrfResult<string>.Fail(PrfErrorCode.AuthenticationTagMismatch);
        }

        return PrfResult<string>.Fail(PrfErrorCode.DecryptionFailed);
    }

    private static KeyPair ParseKeyPairResult(string resultJson)
    {
        using var doc = JsonDocument.Parse(resultJson);
        var root = doc.RootElement;

        if (!root.GetProperty("success").GetBoolean())
        {
            throw new InvalidOperationException(
                root.TryGetProperty("error", out var errorProp) ? errorProp.GetString() : "Key generation failed");
        }

        return new KeyPair(
            root.GetProperty("privateKeyBase64").GetString()!,
            root.GetProperty("publicKeyBase64").GetString()!
        );
    }

    private static PrfResult<DualKeyPair> ParseDualKeyPairResult(string resultJson)
    {
        using var doc = JsonDocument.Parse(resultJson);
        var root = doc.RootElement;

        if (root.GetProperty("success").GetBoolean())
        {
            var keyPair = new DualKeyPair(
                root.GetProperty("x25519PublicKeyBase64").GetString()!,
                root.GetProperty("ed25519PublicKeyBase64").GetString()!
            );
            return PrfResult<DualKeyPair>.Ok(keyPair);
        }

        return PrfResult<DualKeyPair>.Fail(PrfErrorCode.KeyDerivationFailed);
    }
}
