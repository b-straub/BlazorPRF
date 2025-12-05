using System.Runtime.InteropServices.JavaScript;
using System.Runtime.Versioning;
using System.Text.Json;
using BlazorPRF.Json;
using BlazorPRF.Models;

namespace BlazorPRF.Services;

/// <summary>
/// Service for symmetric encryption using PRF-derived keys.
/// </summary>
[SupportedOSPlatform("browser")]
public sealed partial class SymmetricEncryptionService : ISymmetricEncryption
{
    private readonly PrfService _prfService;

    public SymmetricEncryptionService(IPrfService prfService)
    {
        // We need the concrete type to access internal GetPrivateKey
        _prfService = (PrfService)prfService;
    }

    /// <inheritdoc />
    public ValueTask<PrfResult<SymmetricEncryptedMessage>> EncryptAsync(string message, string salt)
    {
        ArgumentException.ThrowIfNullOrEmpty(message);
        ArgumentException.ThrowIfNullOrEmpty(salt);

        // Get the cached private key
        var privateKey = _prfService.GetPrivateKey(salt);
        if (privateKey is null)
        {
            return ValueTask.FromResult(
                PrfResult<SymmetricEncryptedMessage>.Fail(PrfErrorCode.KeyDerivationFailed)
            );
        }

        try
        {
            var keyBase64 = Convert.ToBase64String(privateKey);

            // Call JavaScript encryption
            var resultJson = JsInterop.EncryptSymmetric(message, keyBase64);

            // Clear the key from managed memory
            Array.Clear(privateKey, 0, privateKey.Length);

            // Parse result
            var encrypted = JsonSerializer.Deserialize(resultJson, PrfJsonContext.Default.SymmetricEncryptedMessage);
            if (encrypted is null)
            {
                return ValueTask.FromResult(
                    PrfResult<SymmetricEncryptedMessage>.Fail(PrfErrorCode.EncryptionFailed)
                );
            }

            return ValueTask.FromResult(PrfResult<SymmetricEncryptedMessage>.Ok(encrypted));
        }
        catch
        {
            // Ensure key is cleared even on error
            Array.Clear(privateKey, 0, privateKey.Length);
            return ValueTask.FromResult(
                PrfResult<SymmetricEncryptedMessage>.Fail(PrfErrorCode.EncryptionFailed)
            );
        }
    }

    /// <inheritdoc />
    public ValueTask<PrfResult<string>> DecryptAsync(SymmetricEncryptedMessage encrypted, string salt)
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
            var encryptedJson = JsonSerializer.Serialize(encrypted, PrfJsonContext.Default.SymmetricEncryptedMessage);

            // Call JavaScript decryption
            var resultJson = JsInterop.DecryptSymmetric(encryptedJson, keyBase64);

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
        [JSImport("encryptSymmetric", "blazorPrf")]
        public static partial string EncryptSymmetric(string message, string keyBase64);

        [JSImport("decryptSymmetric", "blazorPrf")]
        public static partial string DecryptSymmetric(string encryptedJson, string keyBase64);
    }
}
