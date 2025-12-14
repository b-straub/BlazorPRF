using System.Runtime.InteropServices.JavaScript;
using System.Runtime.Versioning;

namespace BlazorPRF.BaseCrypto.Wasm.Interop;

/// <summary>
/// JavaScript interop for BlazorPRF.BaseCrypto.Wasm using JSImport.
/// All crypto operations use salt-based key lookup - private keys never leave JS.
/// </summary>
[SupportedOSPlatform("browser")]
internal static partial class BasePrfInterop
{
    private const string ModuleName = "BlazorPRFBase";

    private static bool _initialized;
    private static Task? _initTask;
    private static readonly Lock InitLock = new();

    /// <summary>
    /// Returns true if the JS module has been initialized.
    /// </summary>
    internal static bool IsInitialized => _initialized;

    /// <summary>
    /// Ensures the JS module is imported before use.
    /// </summary>
    internal static async Task EnsureInitializedAsync()
    {
        if (_initialized)
        {
            return;
        }

        Task initTask;
        lock (InitLock)
        {
            if (_initialized)
            {
                return;
            }

            _initTask ??= InitializeAsync();
            initTask = _initTask;
        }

        await initTask;
        _initialized = true;
    }

    private static async Task InitializeAsync()
    {
        // Get base href dynamically
        await JSHost.ImportAsync("BlazorPRFBaseHelper",
            "data:text/javascript,export function getBaseHref() { return document.querySelector('base')?.getAttribute('href') || '/'; }");
        var baseHref = GetBaseHref();
        var modulePath = $"{baseHref}_content/BlazorPRF.BaseCrypto.Wasm/blazorprfbase-wasm.js";

        await JSHost.ImportAsync(ModuleName, modulePath);
    }

    [JSImport("getBaseHref", "BlazorPRFBaseHelper")]
    private static partial string GetBaseHref();

    // ============================================================
    // PRF Support Check
    // ============================================================

    [JSImport("isPrfSupported", ModuleName)]
    internal static partial bool IsPrfSupported();

    [JSImport("isConditionalMediationAvailable", ModuleName)]
    internal static partial Task<bool> IsConditionalMediationAvailableAsync();

    // ============================================================
    // Registration
    // ============================================================

    [JSImport("register", ModuleName)]
    internal static partial Task<string> RegisterAsync(string? displayName);

    // ============================================================
    // Authentication (derives keys and caches in JS)
    // Returns only public info - private keys stay in JS
    // ============================================================

    [JSImport("authenticate", ModuleName)]
    internal static partial Task<string> AuthenticateAsync(
        string credentialIdBase64,
        string saltBase64,
        int? ttlMs);

    [JSImport("authenticateDiscoverable", ModuleName)]
    internal static partial Task<string> AuthenticateDiscoverableAsync(
        string saltBase64,
        int? ttlMs);

    // ============================================================
    // Cache Management
    // ============================================================

    [JSImport("hasCachedKeys", ModuleName)]
    internal static partial bool HasCachedKeys(string saltBase64);

    [JSImport("getCachedPublicInfo", ModuleName)]
    internal static partial string GetCachedPublicInfo(string saltBase64);

    [JSImport("clearCachedKeys", ModuleName)]
    internal static partial void ClearCachedKeys(string saltBase64);

    [JSImport("clearAllCachedKeys", ModuleName)]
    internal static partial void ClearAllCachedKeys();

    // ============================================================
    // Encryption (uses cached keys by salt - key never leaves JS)
    // ============================================================

    [JSImport("encryptAesGcm", ModuleName)]
    internal static partial Task<string> EncryptAesGcmAsync(
        string plaintextBase64,
        string saltBase64);

    [JSImport("decryptAesGcm", ModuleName)]
    internal static partial Task<string> DecryptAesGcmAsync(
        string ciphertextBase64,
        string nonceBase64,
        string saltBase64);

    // ============================================================
    // Signing (uses cached keys by salt - key never leaves JS)
    // ============================================================

    [JSImport("ed25519Sign", ModuleName)]
    internal static partial Task<string> Ed25519SignAsync(
        string messageBase64,
        string saltBase64);

    [JSImport("ed25519Verify", ModuleName)]
    internal static partial Task<bool> Ed25519VerifyAsync(
        string messageBase64,
        string signatureBase64,
        string publicKeyBase64);

    // ============================================================
    // Key Expiration Callback
    // ============================================================

    [JSImport("setKeyExpiredCallback", ModuleName)]
    internal static partial void SetKeyExpiredCallback(
        [JSMarshalAs<JSType.Function<JSType.String>>] Action<string> callback);
}
