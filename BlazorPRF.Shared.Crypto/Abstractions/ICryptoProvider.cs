using BlazorPRF.Shared.Crypto.Models;

namespace BlazorPRF.Shared.Crypto.Abstractions;

/// <summary>
/// Abstraction for cryptographic operations.
/// Implementations: BouncyCastleCryptoProvider (full support), WebCryptoProvider (AES-GCM only).
/// </summary>
public interface ICryptoProvider
{
    /// <summary>
    /// Gets the name of this crypto provider for diagnostics.
    /// </summary>
    string ProviderName { get; }

    /// <summary>
    /// Gets the supported encryption algorithms.
    /// </summary>
    IReadOnlyList<EncryptionAlgorithm> SupportedAlgorithms { get; }

    /// <summary>
    /// Checks if an algorithm is supported by this provider.
    /// </summary>
    bool IsAlgorithmSupported(EncryptionAlgorithm algorithm);

    // ============================================================
    // SYMMETRIC ENCRYPTION
    // ============================================================

    /// <summary>
    /// Encrypts a message using symmetric encryption.
    /// </summary>
    /// <param name="plaintext">The plaintext to encrypt</param>
    /// <param name="key">32-byte encryption key</param>
    /// <param name="algorithm">Encryption algorithm to use</param>
    /// <returns>Encrypted message with nonce</returns>
    ValueTask<PrfResult<SymmetricEncryptedMessage>> EncryptSymmetricAsync(
        string plaintext,
        ReadOnlyMemory<byte> key,
        EncryptionAlgorithm algorithm = EncryptionAlgorithm.AES_GCM);

    /// <summary>
    /// Decrypts a message using symmetric encryption.
    /// </summary>
    /// <param name="encrypted">The encrypted message</param>
    /// <param name="key">32-byte encryption key</param>
    /// <param name="algorithm">Encryption algorithm used</param>
    /// <returns>Decrypted plaintext</returns>
    ValueTask<PrfResult<string>> DecryptSymmetricAsync(
        SymmetricEncryptedMessage encrypted,
        ReadOnlyMemory<byte> key,
        EncryptionAlgorithm algorithm = EncryptionAlgorithm.AES_GCM);

    // ============================================================
    // ASYMMETRIC ENCRYPTION (ECIES: X25519 + symmetric cipher)
    // ============================================================

    /// <summary>
    /// Encrypts a message using ECIES (X25519 key agreement + symmetric cipher).
    /// </summary>
    /// <param name="plaintext">The plaintext to encrypt</param>
    /// <param name="recipientPublicKeyBase64">Recipient's X25519 public key</param>
    /// <param name="algorithm">Symmetric encryption algorithm to use</param>
    /// <returns>Encrypted message with ephemeral public key and nonce</returns>
    ValueTask<PrfResult<EncryptedMessage>> EncryptAsymmetricAsync(
        string plaintext,
        string recipientPublicKeyBase64,
        EncryptionAlgorithm algorithm = EncryptionAlgorithm.AES_GCM);

    /// <summary>
    /// Decrypts a message using ECIES (X25519 key agreement + symmetric cipher).
    /// </summary>
    /// <param name="encrypted">The encrypted message</param>
    /// <param name="privateKey">Recipient's X25519 private key (32 bytes)</param>
    /// <param name="algorithm">Symmetric encryption algorithm used</param>
    /// <returns>Decrypted plaintext</returns>
    ValueTask<PrfResult<string>> DecryptAsymmetricAsync(
        EncryptedMessage encrypted,
        ReadOnlyMemory<byte> privateKey,
        EncryptionAlgorithm algorithm = EncryptionAlgorithm.AES_GCM);

    // ============================================================
    // ED25519 DIGITAL SIGNATURES
    // ============================================================

    /// <summary>
    /// Signs a message with an Ed25519 private key.
    /// </summary>
    /// <param name="message">The message to sign</param>
    /// <param name="privateKey">Ed25519 private key (32-byte seed)</param>
    /// <returns>Base64-encoded signature (64 bytes)</returns>
    ValueTask<PrfResult<string>> SignAsync(
        string message,
        ReadOnlyMemory<byte> privateKey);

    /// <summary>
    /// Verifies an Ed25519 signature.
    /// </summary>
    /// <param name="message">The original message</param>
    /// <param name="signatureBase64">Base64-encoded signature</param>
    /// <param name="publicKeyBase64">Base64-encoded Ed25519 public key</param>
    /// <returns>True if signature is valid</returns>
    ValueTask<bool> VerifyAsync(
        string message,
        string signatureBase64,
        string publicKeyBase64);

    // ============================================================
    // KEY GENERATION
    // ============================================================

    /// <summary>
    /// Derives an X25519 keypair from a PRF seed.
    /// </summary>
    /// <param name="prfSeed">32-byte PRF seed</param>
    /// <returns>X25519 keypair</returns>
    ValueTask<KeyPair> DeriveX25519KeyPairAsync(ReadOnlyMemory<byte> prfSeed);

    /// <summary>
    /// Derives an Ed25519 keypair from a PRF seed.
    /// </summary>
    /// <param name="prfSeed">32-byte PRF seed</param>
    /// <returns>Ed25519 keypair</returns>
    ValueTask<KeyPair> DeriveEd25519KeyPairAsync(ReadOnlyMemory<byte> prfSeed);

    /// <summary>
    /// Derives both X25519 and Ed25519 keypairs from a single PRF seed.
    /// </summary>
    /// <param name="prfSeed">32-byte PRF seed</param>
    /// <returns>Both keypairs</returns>
    ValueTask<DualKeyPairFull> DeriveDualKeyPairAsync(ReadOnlyMemory<byte> prfSeed);

    /// <summary>
    /// Generates a cryptographically secure random salt.
    /// </summary>
    /// <param name="length">Length in bytes</param>
    /// <returns>Base64-encoded random salt</returns>
    ValueTask<string> GenerateSaltAsync(int length = 32);

    // ============================================================
    // KEY-ID BASED OPERATIONS (Optional - for providers with JS key caching)
    // ============================================================

    /// <summary>
    /// Indicates whether this provider supports keyId-based operations.
    /// When true, keys can be cached internally (e.g., in JS) and operations
    /// can be performed using keyId instead of passing key bytes.
    /// </summary>
    bool SupportsKeyIdOperations => false;

    /// <summary>
    /// Stores and derives keys from PRF seed, caching them by keyId.
    /// Only available when <see cref="SupportsKeyIdOperations"/> is true.
    /// </summary>
    /// <param name="keyId">Unique identifier for the cached keys</param>
    /// <param name="prfSeed">32-byte PRF seed</param>
    /// <param name="ttlMs">Time-to-live in milliseconds, null for no expiration</param>
    /// <returns>Public keys (X25519 and Ed25519)</returns>
    ValueTask<PrfResult<DualKeyPair>> StoreKeysAsync(string keyId, ReadOnlyMemory<byte> prfSeed, int? ttlMs) =>
        ValueTask.FromResult(PrfResult<DualKeyPair>.Fail(PrfErrorCode.NOT_SUPPORTED));

    /// <summary>
    /// Gets the public keys for a cached key set.
    /// Only available when <see cref="SupportsKeyIdOperations"/> is true.
    /// </summary>
    ValueTask<PrfResult<DualKeyPair>> GetPublicKeysAsync(string keyId) =>
        ValueTask.FromResult(PrfResult<DualKeyPair>.Fail(PrfErrorCode.NOT_SUPPORTED));

    /// <summary>
    /// Checks if keys are cached for the given keyId.
    /// Only available when <see cref="SupportsKeyIdOperations"/> is true.
    /// </summary>
    bool HasCachedKey(string keyId) => false;

    /// <summary>
    /// Removes cached keys for the given keyId.
    /// Only available when <see cref="SupportsKeyIdOperations"/> is true.
    /// </summary>
    void RemoveCachedKey(string keyId) { }

    /// <summary>
    /// Signs a message using cached Ed25519 key.
    /// Only available when <see cref="SupportsKeyIdOperations"/> is true.
    /// </summary>
    ValueTask<PrfResult<string>> SignWithKeyIdAsync(string message, string keyId) =>
        ValueTask.FromResult(PrfResult<string>.Fail(PrfErrorCode.NOT_SUPPORTED));

    /// <summary>
    /// Encrypts using cached symmetric key.
    /// Only available when <see cref="SupportsKeyIdOperations"/> is true.
    /// </summary>
    ValueTask<PrfResult<SymmetricEncryptedMessage>> EncryptSymmetricWithKeyIdAsync(
        string plaintext,
        string keyId,
        EncryptionAlgorithm algorithm = EncryptionAlgorithm.AES_GCM) =>
        ValueTask.FromResult(PrfResult<SymmetricEncryptedMessage>.Fail(PrfErrorCode.NOT_SUPPORTED));

    /// <summary>
    /// Decrypts using cached symmetric key.
    /// Only available when <see cref="SupportsKeyIdOperations"/> is true.
    /// </summary>
    ValueTask<PrfResult<string>> DecryptSymmetricWithKeyIdAsync(
        SymmetricEncryptedMessage encrypted,
        string keyId,
        EncryptionAlgorithm algorithm = EncryptionAlgorithm.AES_GCM) =>
        ValueTask.FromResult(PrfResult<string>.Fail(PrfErrorCode.NOT_SUPPORTED));

    /// <summary>
    /// Decrypts asymmetrically using cached X25519 private key.
    /// Only available when <see cref="SupportsKeyIdOperations"/> is true.
    /// </summary>
    ValueTask<PrfResult<string>> DecryptAsymmetricWithKeyIdAsync(
        EncryptedMessage encrypted,
        string keyId,
        EncryptionAlgorithm algorithm = EncryptionAlgorithm.AES_GCM) =>
        ValueTask.FromResult(PrfResult<string>.Fail(PrfErrorCode.NOT_SUPPORTED));
}
