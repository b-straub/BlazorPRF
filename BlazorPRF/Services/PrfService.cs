using System.Runtime.InteropServices.JavaScript;
using System.Runtime.Versioning;
using System.Text.Json;
using BlazorPRF.Configuration;
using BlazorPRF.Crypto;
using BlazorPRF.Json;
using BlazorPRF.Models;
using Microsoft.Extensions.Options;
using R3;

namespace BlazorPRF.Services;

/// <summary>
/// Implementation of PRF service using JSImport for WebAuthn operations.
/// </summary>
[SupportedOSPlatform("browser")]
public sealed partial class PrfService : IPrfService, IAsyncDisposable
{
    private readonly PrfOptions _options;
    private readonly KeyCacheOptions _cacheOptions;
    private readonly ISecureKeyCache _keyCache;
    private readonly SemaphoreSlim _initLock = new(1, 1);
    private bool _initialized;

    // Cache for public keys (not sensitive, can store directly)
    private readonly Dictionary<string, string> _publicKeyCache = new();

    /// <inheritdoc />
    public KeyCacheStrategy CacheStrategy => _cacheOptions.Strategy;

    /// <inheritdoc />
    public Observable<string> KeyExpired => _keyCache.KeyExpired;

    public PrfService(
        IOptions<PrfOptions> options,
        IOptions<KeyCacheOptions> cacheOptions,
        ISecureKeyCache keyCache)
    {
        _options = options.Value;
        _cacheOptions = cacheOptions.Value;
        _keyCache = keyCache;
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
            var modulePath = $"{baseHref}_content/BlazorPRF/blazor-prf.js";

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
        var jsOptions = new JsPrfOptions(
            _options.RpName,
            _options.RpId,
            _options.TimeoutMs,
            _options.AuthenticatorAttachment == AuthenticatorAttachment.Platform ? "platform" : "cross-platform"
        );

        return JsonSerializer.Serialize(jsOptions, PrfJsonContext.Default.JsPrfOptions);
    }

    /// <inheritdoc />
    public async ValueTask<bool> IsPrfSupportedAsync()
    {
        await EnsureInitializedAsync();
        return await JsInterop.IsPrfSupported();
    }

    /// <inheritdoc />
    public async ValueTask<PrfResult<PrfCredential>> RegisterAsync(string? displayName = null)
    {
        await EnsureInitializedAsync();

        var resultJson = await JsInterop.Register(displayName, GetJsOptions());
        var result = JsonSerializer.Deserialize(resultJson, PrfJsonContext.Default.PrfResultPrfCredential);

        return result ?? PrfResult<PrfCredential>.Fail(PrfErrorCode.RegistrationFailed);
    }

    /// <inheritdoc />
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
            return PrfResult<string>.Fail(PrfErrorCode.KeyDerivationFailed);
        }

        if (!result.Success || result.Value is null)
        {
            if (result.Cancelled)
            {
                return PrfResult<string>.UserCancelled();
            }

            return PrfResult<string>.Fail(result.ErrorCode ?? PrfErrorCode.KeyDerivationFailed);
        }

        // Derive keypair from PRF output in C# (never exposed to JS)
        var keypair = KeyDerivation.DeriveKeypairFromPrf(result.Value);

        // Cache the private key securely
        var privateKeyBytes = Convert.FromBase64String(keypair.PrivateKeyBase64);
        _keyCache.Store(cacheKey, privateKeyBytes);

        // Clear the byte array after storing
        Array.Clear(privateKeyBytes, 0, privateKeyBytes.Length);

        // Cache the public key (not sensitive)
        _publicKeyCache[salt] = keypair.PublicKeyBase64;

        return PrfResult<string>.Ok(keypair.PublicKeyBase64);
    }

    /// <inheritdoc />
    public async ValueTask<PrfResult<(string CredentialId, string PublicKey)>> DeriveKeysDiscoverableAsync(string salt)
    {
        ArgumentException.ThrowIfNullOrEmpty(salt);

        await EnsureInitializedAsync();

        // Get raw PRF output from JS (WebAuthn) with discoverable credential
        var resultJson = await JsInterop.EvaluatePrfDiscoverableOutput(salt, GetJsOptions());
        var result = JsonSerializer.Deserialize(resultJson, PrfJsonContext.Default.PrfResultDiscoverablePrfOutput);

        if (result is null)
        {
            return PrfResult<(string, string)>.Fail(PrfErrorCode.KeyDerivationFailed);
        }

        if (!result.Success || result.Value is null)
        {
            if (result.Cancelled)
            {
                return PrfResult<(string, string)>.UserCancelled();
            }

            return PrfResult<(string, string)>.Fail(result.ErrorCode ?? PrfErrorCode.KeyDerivationFailed);
        }

        // Derive keypair from PRF output in C# (never exposed to JS)
        var keypair = KeyDerivation.DeriveKeypairFromPrf(result.Value.PrfOutput);

        // Cache the private key securely
        var cacheKey = GetCacheKey(salt);
        var privateKeyBytes = Convert.FromBase64String(keypair.PrivateKeyBase64);
        _keyCache.Store(cacheKey, privateKeyBytes);

        // Clear the byte array after storing
        Array.Clear(privateKeyBytes, 0, privateKeyBytes.Length);

        // Cache the public key (not sensitive)
        _publicKeyCache[salt] = keypair.PublicKeyBase64;

        return PrfResult<(string, string)>.Ok((result.Value.CredentialId, keypair.PublicKeyBase64));
    }

    /// <inheritdoc />
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

    /// <inheritdoc />
    public bool HasCachedKeys(string salt)
    {
        if (string.IsNullOrEmpty(salt))
        {
            return false;
        }

        return _keyCache.Contains(GetCacheKey(salt));
    }

    /// <inheritdoc />
    public void ClearKeys()
    {
        _keyCache.Clear();
        _publicKeyCache.Clear();
    }

    private static string GetCacheKey(string salt) => $"prf-key:{salt}";

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
