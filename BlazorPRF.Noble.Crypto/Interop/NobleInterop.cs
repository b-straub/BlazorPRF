using System.Runtime.InteropServices.JavaScript;
using System.Runtime.Versioning;

namespace BlazorPRF.Noble.Crypto.Interop;

/// <summary>
/// JavaScript interop for Noble.js + SubtleCrypto hybrid crypto operations.
/// </summary>
[SupportedOSPlatform("browser")]
internal static partial class NobleInterop
{
    private const string ModuleName = "blazorPrfNoble";
    private static readonly SemaphoreSlim InitSemaphore = new(1, 1);
    private static bool _initialized;

    /// <summary>
    /// Ensures the JavaScript module is loaded.
    /// Uses SemaphoreSlim for proper async initialization without deadlock risk.
    /// </summary>
    public static async ValueTask EnsureInitializedAsync()
    {
        if (_initialized)
        {
            return;
        }

        await InitSemaphore.WaitAsync();
        try
        {
            if (_initialized)
            {
                return;
            }

            // Get base href dynamically
            await JSHost.ImportAsync("NobleHelper", "data:text/javascript,export function getBaseHref() { return document.querySelector('base')?.getAttribute('href') || '/'; }");
            var baseHref = GetBaseHref();
            var modulePath = $"{baseHref}_content/BlazorPRF.Noble.Crypto/blazorprf-noble.js";

            await JSHost.ImportAsync(ModuleName, modulePath);
            _initialized = true;
        }
        finally
        {
            InitSemaphore.Release();
        }
    }

    [JSImport("getBaseHref", "NobleHelper")]
    private static partial string GetBaseHref();

    // ============================================================
    // X25519 KEY OPERATIONS
    // ============================================================

    [JSImport("generateX25519KeyPair", ModuleName)]
    public static partial string GenerateX25519KeyPair();

    [JSImport("getX25519PublicKey", ModuleName)]
    public static partial string GetX25519PublicKey(string privateKeyBase64);

    [JSImport("deriveX25519KeyPair", ModuleName)]
    public static partial string DeriveX25519KeyPair(string prfSeedBase64);

    // ============================================================
    // ED25519 SIGNING
    // ============================================================

    [JSImport("generateEd25519KeyPair", ModuleName)]
    public static partial string GenerateEd25519KeyPair();

    [JSImport("getEd25519PublicKey", ModuleName)]
    public static partial string GetEd25519PublicKey(string privateKeyBase64);

    [JSImport("deriveEd25519KeyPair", ModuleName)]
    public static partial string DeriveEd25519KeyPair(string prfSeedBase64);

    [JSImport("ed25519Sign", ModuleName)]
    public static partial string Ed25519Sign(string messageBase64, string privateKeyBase64);

    [JSImport("ed25519Verify", ModuleName)]
    public static partial bool Ed25519Verify(string messageBase64, string signatureBase64, string publicKeyBase64);

    // ============================================================
    // DUAL KEY DERIVATION
    // ============================================================

    [JSImport("deriveDualKeyPair", ModuleName)]
    public static partial string DeriveDualKeyPair(string prfSeedBase64);

    // ============================================================
    // CHACHA20-POLY1305 SYMMETRIC ENCRYPTION
    // ============================================================

    [JSImport("encryptChaCha", ModuleName)]
    public static partial string EncryptChaCha(string plaintextBase64, string keyBase64);

    [JSImport("decryptChaCha", ModuleName)]
    public static partial string DecryptChaCha(string ciphertextBase64, string nonceBase64, string keyBase64);

    // ============================================================
    // AES-GCM SYMMETRIC ENCRYPTION (SubtleCrypto)
    // ============================================================

    [JSImport("encryptAesGcm", ModuleName)]
    public static partial Task<string> EncryptAesGcmAsync(string plaintextBase64, string keyBase64);

    [JSImport("decryptAesGcm", ModuleName)]
    public static partial Task<string> DecryptAesGcmAsync(string ciphertextBase64, string nonceBase64, string keyBase64);

    // ============================================================
    // ECIES ASYMMETRIC ENCRYPTION (X25519 + ChaCha20-Poly1305)
    // ============================================================

    [JSImport("encryptAsymmetricChaCha", ModuleName)]
    public static partial string EncryptAsymmetricChaCha(string plaintextBase64, string recipientPublicKeyBase64);

    [JSImport("decryptAsymmetricChaCha", ModuleName)]
    public static partial string DecryptAsymmetricChaCha(
        string ephemeralPublicKeyBase64,
        string ciphertextBase64,
        string nonceBase64,
        string privateKeyBase64);

    // ============================================================
    // ECIES ASYMMETRIC ENCRYPTION (X25519 + AES-GCM)
    // ============================================================

    [JSImport("encryptAsymmetricAesGcm", ModuleName)]
    public static partial Task<string> EncryptAsymmetricAesGcmAsync(string plaintextBase64, string recipientPublicKeyBase64);

    [JSImport("decryptAsymmetricAesGcm", ModuleName)]
    public static partial Task<string> DecryptAsymmetricAesGcmAsync(
        string ephemeralPublicKeyBase64,
        string ciphertextBase64,
        string nonceBase64,
        string privateKeyBase64);

    // ============================================================
    // KEY DERIVATION
    // ============================================================

    [JSImport("deriveHkdfKey", ModuleName)]
    public static partial Task<string> DeriveHkdfKey(string prfSeedBase64, string domain);

    // ============================================================
    // UTILITY
    // ============================================================

    [JSImport("generateRandomBytes", ModuleName)]
    public static partial string GenerateRandomBytes(int length);

    [JSImport("isSupported", ModuleName)]
    public static partial bool IsSupported();

    // ============================================================
    // KEY CACHE MANAGEMENT (Keys stay in JS, C# only uses keyId)
    // ============================================================

    /// <summary>
    /// Store and derive all keys from PRF seed, caching in JS.
    /// Keys stay in JS - C# only uses keyId for subsequent operations.
    /// </summary>
    [JSImport("storeKeys", ModuleName)]
    public static partial Task<string> StoreKeysAsync(string keyId, string prfSeedBase64, int? ttlMs);

    /// <summary>
    /// Get public keys for a cached key set.
    /// </summary>
    [JSImport("getPublicKeys", ModuleName)]
    public static partial string GetPublicKeys(string keyId);

    /// <summary>
    /// Check if a key exists and is not expired.
    /// </summary>
    [JSImport("hasKey", ModuleName)]
    public static partial bool HasKey(string keyId);

    /// <summary>
    /// Remove and securely clear a cached key set.
    /// </summary>
    [JSImport("removeKeys", ModuleName)]
    public static partial void RemoveKeys(string keyId);

    /// <summary>
    /// Remove all cached keys.
    /// </summary>
    [JSImport("clearAllKeys", ModuleName)]
    public static partial void ClearAllKeys();

    // ============================================================
    // CACHED KEY OPERATIONS (use keyId, keys stay in JS)
    // ============================================================

    /// <summary>
    /// Sign with Ed25519 using cached key (key never leaves JS).
    /// </summary>
    [JSImport("signWithCachedKey", ModuleName)]
    public static partial string SignWithCachedKey(string keyId, string messageBase64);

    /// <summary>
    /// Encrypt symmetric with ChaCha20-Poly1305 using cached key.
    /// </summary>
    [JSImport("encryptSymmetricCachedChaCha", ModuleName)]
    public static partial string EncryptSymmetricCachedChaCha(string keyId, string plaintextBase64);

    /// <summary>
    /// Decrypt symmetric with ChaCha20-Poly1305 using cached key.
    /// </summary>
    [JSImport("decryptSymmetricCachedChaCha", ModuleName)]
    public static partial string DecryptSymmetricCachedChaCha(string keyId, string ciphertextBase64, string nonceBase64);

    /// <summary>
    /// Encrypt symmetric with AES-GCM using cached CryptoKey (hardware accelerated).
    /// </summary>
    [JSImport("encryptSymmetricCachedAesGcm", ModuleName)]
    public static partial Task<string> EncryptSymmetricCachedAesGcmAsync(string keyId, string plaintextBase64);

    /// <summary>
    /// Decrypt symmetric with AES-GCM using cached CryptoKey (hardware accelerated).
    /// </summary>
    [JSImport("decryptSymmetricCachedAesGcm", ModuleName)]
    public static partial Task<string> DecryptSymmetricCachedAesGcmAsync(string keyId, string ciphertextBase64, string nonceBase64);

    /// <summary>
    /// Decrypt asymmetric (ECIES) with ChaCha20-Poly1305 using cached X25519 private key.
    /// </summary>
    [JSImport("decryptAsymmetricCachedChaCha", ModuleName)]
    public static partial string DecryptAsymmetricCachedChaCha(
        string keyId,
        string ephemeralPublicKeyBase64,
        string ciphertextBase64,
        string nonceBase64);

    /// <summary>
    /// Decrypt asymmetric (ECIES) with AES-GCM using cached X25519 private key.
    /// </summary>
    [JSImport("decryptAsymmetricCachedAesGcm", ModuleName)]
    public static partial Task<string> DecryptAsymmetricCachedAesGcmAsync(
        string keyId,
        string ephemeralPublicKeyBase64,
        string ciphertextBase64,
        string nonceBase64);
}
