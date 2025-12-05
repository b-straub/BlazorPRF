using System.Runtime.InteropServices.JavaScript;
using System.Runtime.Versioning;
using System.Text.Json;
using BlazorPRF.Json;
using BlazorPRF.Models;

namespace BlazorPRF.Services;

/// <summary>
/// Service for asymmetric (ECIES) encryption using PRF-derived keys.
/// </summary>
[SupportedOSPlatform("browser")]
public sealed partial class AsymmetricEncryptionService : IAsymmetricEncryption
{
    private readonly PrfService _prfService;

    public AsymmetricEncryptionService(IPrfService prfService)
    {
        // We need the concrete type to access internal GetPrivateKey
        _prfService = (PrfService)prfService;
    }

    /// <inheritdoc />
    public ValueTask<PrfResult<EncryptedMessage>> EncryptAsync(string message, string recipientPublicKey)
    {
        ArgumentException.ThrowIfNullOrEmpty(message);
        ArgumentException.ThrowIfNullOrEmpty(recipientPublicKey);

        try
        {
            // Call JavaScript encryption (no private key needed)
            var resultJson = JsInterop.EncryptAsymmetric(message, recipientPublicKey);

            // Parse result - error codes come from JS
            var result = JsonSerializer.Deserialize(resultJson, PrfJsonContext.Default.PrfResultEncryptedMessage);
            return ValueTask.FromResult(result ?? PrfResult<EncryptedMessage>.Fail(PrfErrorCode.EncryptionFailed));
        }
        catch
        {
            return ValueTask.FromResult(
                PrfResult<EncryptedMessage>.Fail(PrfErrorCode.EncryptionFailed)
            );
        }
    }

    /// <inheritdoc />
    public ValueTask<PrfResult<string>> DecryptAsync(EncryptedMessage encrypted, string salt)
    {
        ArgumentNullException.ThrowIfNull(encrypted);
        ArgumentException.ThrowIfNullOrEmpty(salt);

        // Get the cached private key
        var privateKey = _prfService.GetPrivateKey(salt);
        if (privateKey is null)
        {
            return ValueTask.FromResult(
                PrfResult<string>.Fail(PrfErrorCode.KeyDerivationFailed)
            );
        }

        try
        {
            var keyBase64 = Convert.ToBase64String(privateKey);
            var encryptedJson = JsonSerializer.Serialize(encrypted, PrfJsonContext.Default.EncryptedMessage);

            // Call JavaScript decryption
            var resultJson = JsInterop.DecryptAsymmetric(encryptedJson, keyBase64);

            // Clear the key from managed memory
            Array.Clear(privateKey, 0, privateKey.Length);

            // Parse result - error codes come from JS
            var result = JsonSerializer.Deserialize(resultJson, PrfJsonContext.Default.PrfResultString);
            return ValueTask.FromResult(result ?? PrfResult<string>.Fail(PrfErrorCode.DecryptionFailed));
        }
        catch
        {
            // Ensure key is cleared even on error
            Array.Clear(privateKey, 0, privateKey.Length);
            return ValueTask.FromResult(
                PrfResult<string>.Fail(PrfErrorCode.DecryptionFailed)
            );
        }
    }

    private static partial class JsInterop
    {
        [JSImport("encryptAsymmetric", "blazorPrf")]
        public static partial string EncryptAsymmetric(string message, string recipientPublicKeyBase64);

        [JSImport("decryptAsymmetric", "blazorPrf")]
        public static partial string DecryptAsymmetric(string encryptedJson, string privateKeyBase64);
    }
}
