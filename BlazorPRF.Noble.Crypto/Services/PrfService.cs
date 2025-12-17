using System.Runtime.InteropServices.JavaScript;
using System.Runtime.Versioning;
using System.Text.Json;
using BlazorPRF.Noble.Crypto.Json;
using BlazorPRF.Shared.Crypto.Abstractions;
using BlazorPRF.Shared.Crypto.Configuration;
using BlazorPRF.Shared.Crypto.Models;
using BlazorPRF.Shared.Crypto.Services;
using Microsoft.Extensions.Options;
using R3;

namespace BlazorPRF.Noble.Crypto.Services;

/// <summary>
/// Implementation of PRF service using JSImport for WebAuthn operations
/// and ICryptoProvider for key derivation (Noble.js implementation).
/// </summary>
[SupportedOSPlatform("browser")]
public sealed partial class PrfService : IPrfService, IEd25519PublicKeyProvider, IAsyncDisposable
{
    private readonly PrfOptions _options;
    private readonly KeyCacheOptions _cacheOptions;
    private readonly ISecureKeyCache _keyCache;
    private readonly ICryptoProvider _cryptoProvider;
    private readonly SemaphoreSlim _initLock = new(1, 1);
    private bool _initialized;

    // Cache for public keys (not sensitive, can store directly)
    private readonly Dictionary<string, string> _publicKeyCache = new();
    private readonly Dictionary<string, string> _ed25519PublicKeyCache = new();

       public KeyCacheStrategy CacheStrategy => _cacheOptions.Strategy;

       public Observable<string> KeyExpired => _keyCache.KeyExpired;

    public PrfService(
        IOptions<PrfOptions> options,
        IOptions<KeyCacheOptions> cacheOptions,
        ISecureKeyCache keyCache,
        ICryptoProvider cryptoProvider)
    {
        _options = options.Value;
        _cacheOptions = cacheOptions.Value;
        _keyCache = keyCache;
        _cryptoProvider = cryptoProvider;
    }

    /// <summary>
    /// Ensure JavaScript module is loaded.
    /// </summary>
    private async ValueTask EnsureInitializedAsync()
    {
        if (_initialized)
        {
            return;
        }

        await _initLock.WaitAsync();
        try
        {
            if (_initialized)
            {
                return;
            }

            // Get base href dynamically and construct absolute path
            await JSHost.ImportAsync("BlazorPrfHelper", "data:text/javascript,export function getBaseHref() { return document.querySelector('base')?.getAttribute('href') || '/'; }");
            var baseHref = GetBaseHref();
            var modulePath = $"{baseHref}_content/BlazorPRF.Noble.Crypto/blazorprf-noble.js";

            await JSHost.ImportAsync("blazorPrf", modulePath);
            _initialized = true;
        }
        finally
        {
            _initLock.Release();
        }
    }

    [JSImport("getBaseHref", "BlazorPrfHelper")]
    private static partial string GetBaseHref();

    /// <summary>
    /// Get JavaScript options object.
    /// </summary>
    private string GetJsOptions()
    {
        var attachment = _options.AuthenticatorAttachment switch
        {
            AuthenticatorAttachment.PLATFORM => "platform",
            AuthenticatorAttachment.CROSS_PLATFORM => "cross-platform",
            AuthenticatorAttachment.ANY => "any",
            _ => "platform"
        };

        var jsOptions = new JsPrfOptions(
            _options.RpName,
            _options.RpId,
            _options.TimeoutMs,
            attachment
        );

        return JsonSerializer.Serialize(jsOptions, PrfJsonContext.Default.JsPrfOptions);
    }

       public async ValueTask<bool> IsPrfSupportedAsync()
    {
        await EnsureInitializedAsync();
        return await JsInterop.IsPrfSupported();
    }

       public async ValueTask<PrfResult<PrfCredential>> RegisterAsync(string? displayName = null)
    {
        await EnsureInitializedAsync();

        var resultJson = await JsInterop.Register(displayName, GetJsOptions());
        var result = JsonSerializer.Deserialize(resultJson, PrfJsonContext.Default.PrfResultPrfCredential);

        return result ?? PrfResult<PrfCredential>.Fail(PrfErrorCode.REGISTRATION_FAILED);
    }

       public async ValueTask<PrfResult<string>> DeriveKeysAsync(string credentialId, string salt)
    {
        ArgumentException.ThrowIfNullOrEmpty(credentialId);
        ArgumentException.ThrowIfNullOrEmpty(salt);

        // Check cache first
        var cacheKey = GetCacheKey(salt);
        if (_keyCache.Contains(cacheKey) && _publicKeyCache.TryGetValue(salt, out var cachedPublicKey))
        {
            return PrfResult<string>.Ok(cachedPublicKey);
        }

        await EnsureInitializedAsync();

        // Get raw PRF output from JS (WebAuthn)
        var resultJson = await JsInterop.EvaluatePrfOutput(credentialId, salt, GetJsOptions());
        var result = JsonSerializer.Deserialize(resultJson, PrfJsonContext.Default.PrfResultString);

        if (result is null)
        {
            return PrfResult<string>.Fail(PrfErrorCode.KEY_DERIVATION_FAILED);
        }

        if (!result.Success || result.Value is null)
        {
            if (result.Cancelled)
            {
                return PrfResult<string>.UserCancelled();
            }

            return PrfResult<string>.Fail(result.ErrorCode ?? PrfErrorCode.KEY_DERIVATION_FAILED);
        }

        // Store the raw PRF seed for domain-specific key derivation
        var prfSeedBytes = Convert.FromBase64String(result.Value);
        var prfSeedCacheKey = GetPrfSeedCacheKey(salt);
        _keyCache.Store(prfSeedCacheKey, prfSeedBytes);

        // Derive both X25519 (encryption) and Ed25519 (signing) keypairs using ICryptoProvider
        var dualKeys = await _cryptoProvider.DeriveDualKeyPairAsync(prfSeedBytes);

        // Cache the X25519 private key securely
        var x25519PrivateKeyBytes = Convert.FromBase64String(dualKeys.X25519PrivateKey);
        _keyCache.Store(cacheKey, x25519PrivateKeyBytes);
        Array.Clear(x25519PrivateKeyBytes, 0, x25519PrivateKeyBytes.Length);

        // Cache the Ed25519 private key securely
        var ed25519CacheKey = GetEd25519CacheKey(salt);
        var ed25519PrivateKeyBytes = Convert.FromBase64String(dualKeys.Ed25519PrivateKey);
        _keyCache.Store(ed25519CacheKey, ed25519PrivateKeyBytes);
        Array.Clear(ed25519PrivateKeyBytes, 0, ed25519PrivateKeyBytes.Length);

        // Clear the PRF seed from managed memory (it's now in unmanaged cache)
        Array.Clear(prfSeedBytes, 0, prfSeedBytes.Length);

        // Cache the public keys (not sensitive)
        _publicKeyCache[salt] = dualKeys.X25519PublicKey;
        _ed25519PublicKeyCache[salt] = dualKeys.Ed25519PublicKey;

        return PrfResult<string>.Ok(dualKeys.X25519PublicKey);
    }

       public async ValueTask<PrfResult<(string CredentialId, string PublicKey)>> DeriveKeysDiscoverableAsync(string salt)
    {
        ArgumentException.ThrowIfNullOrEmpty(salt);

        await EnsureInitializedAsync();

        // Get raw PRF output from JS (WebAuthn) with discoverable credential
        var resultJson = await JsInterop.EvaluatePrfDiscoverableOutput(salt, GetJsOptions());
        var result = JsonSerializer.Deserialize(resultJson, PrfJsonContext.Default.PrfResultDiscoverablePrfOutput);

        if (result is null)
        {
            return PrfResult<(string, string)>.Fail(PrfErrorCode.KEY_DERIVATION_FAILED);
        }

        if (!result.Success || result.Value is null)
        {
            if (result.Cancelled)
            {
                return PrfResult<(string, string)>.UserCancelled();
            }

            return PrfResult<(string, string)>.Fail(result.ErrorCode ?? PrfErrorCode.KEY_DERIVATION_FAILED);
        }

        // Store the raw PRF seed for domain-specific key derivation
        var prfSeedBytes = Convert.FromBase64String(result.Value.PrfOutput);
        var prfSeedCacheKey = GetPrfSeedCacheKey(salt);
        _keyCache.Store(prfSeedCacheKey, prfSeedBytes);

        // Derive both X25519 (encryption) and Ed25519 (signing) keypairs using ICryptoProvider
        var dualKeys = await _cryptoProvider.DeriveDualKeyPairAsync(prfSeedBytes);

        // Cache the X25519 private key securely
        var cacheKey = GetCacheKey(salt);
        var x25519PrivateKeyBytes = Convert.FromBase64String(dualKeys.X25519PrivateKey);
        _keyCache.Store(cacheKey, x25519PrivateKeyBytes);
        Array.Clear(x25519PrivateKeyBytes, 0, x25519PrivateKeyBytes.Length);

        // Cache the Ed25519 private key securely
        var ed25519CacheKey = GetEd25519CacheKey(salt);
        var ed25519PrivateKeyBytes = Convert.FromBase64String(dualKeys.Ed25519PrivateKey);
        _keyCache.Store(ed25519CacheKey, ed25519PrivateKeyBytes);
        Array.Clear(ed25519PrivateKeyBytes, 0, ed25519PrivateKeyBytes.Length);

        // Clear the PRF seed from managed memory (it's now in unmanaged cache)
        Array.Clear(prfSeedBytes, 0, prfSeedBytes.Length);

        // Cache the public keys (not sensitive)
        _publicKeyCache[salt] = dualKeys.X25519PublicKey;
        _ed25519PublicKeyCache[salt] = dualKeys.Ed25519PublicKey;

        return PrfResult<(string, string)>.Ok((result.Value.CredentialId, dualKeys.X25519PublicKey));
    }

       public string? GetCachedPublicKey(string salt)
    {
        if (string.IsNullOrEmpty(salt))
        {
            return null;
        }

        var cacheKey = GetCacheKey(salt);
        if (!_keyCache.Contains(cacheKey))
        {
            return null;
        }

        return _publicKeyCache.GetValueOrDefault(salt);
    }

       public bool HasCachedKeys(string salt)
    {
        if (string.IsNullOrEmpty(salt))
        {
            return false;
        }

        return _keyCache.Contains(GetCacheKey(salt));
    }

       public void ClearKeys()
    {
        _keyCache.Clear();
        _publicKeyCache.Clear();
        _ed25519PublicKeyCache.Clear();
    }

       public string? GetEd25519PublicKey(string keyIdentifier)
    {
        if (string.IsNullOrEmpty(keyIdentifier))
        {
            return null;
        }

        return _ed25519PublicKeyCache.GetValueOrDefault(keyIdentifier);
    }

    private static string GetCacheKey(string salt) => $"prf-key:{salt}";
    private static string GetEd25519CacheKey(string salt) => $"prf-ed25519-key:{salt}";
    internal static string GetPrfSeedCacheKey(string salt) => $"prf-seed:{salt}";

    public ValueTask DisposeAsync()
    {
        ClearKeys();
        _initLock.Dispose();
        return ValueTask.CompletedTask;
    }

    /// <summary>
    /// JavaScript interop methods.
    /// WebAuthn/PRF only - crypto operations happen in C#.
    /// </summary>
    private static partial class JsInterop
    {
        [JSImport("isPrfSupported", "blazorPrf")]
        public static partial Task<bool> IsPrfSupported();

        [JSImport("register", "blazorPrf")]
        public static partial Task<string> Register(string? displayName, string optionsJson);

        [JSImport("evaluatePrfOutput", "blazorPrf")]
        public static partial Task<string> EvaluatePrfOutput(string credentialIdBase64, string salt, string optionsJson);

        [JSImport("evaluatePrfDiscoverableOutput", "blazorPrf")]
        public static partial Task<string> EvaluatePrfDiscoverableOutput(string salt, string optionsJson);
    }
}
