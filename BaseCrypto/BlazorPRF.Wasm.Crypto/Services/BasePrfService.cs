using System.Runtime.Versioning;
using System.Text;
using System.Text.Json;
using BlazorPRF.Wasm.Crypto.Interop;
using BlazorPRF.Wasm.Crypto.Models;

namespace BlazorPRF.Wasm.Crypto.Services;

/// <summary>
/// Implementation of IBasePrfService using WebAuthn PRF and WebCrypto.
/// All private keys remain in JavaScript as non-extractable CryptoKey objects.
/// </summary>
[SupportedOSPlatform("browser")]
public sealed class BasePrfService : IBasePrfService
{
    private bool _callbackRegistered;

       public event Action<string>? KeyExpired;

       public bool IsInitialized => BasePrfInterop.IsInitialized;

    public bool IsPrfSupported()
    {
        return BasePrfInterop.IsPrfSupported();
    }

    public async Task<bool> IsConditionalMediationAvailableAsync()
    {
        await EnsureInitializedAsync();
        return await BasePrfInterop.IsConditionalMediationAvailableAsync();
    }

    public async Task<BasePrfResult<string>> RegisterAsync(string? displayName = null)
    {
        await EnsureInitializedAsync();

        var resultJson = await BasePrfInterop.RegisterAsync(displayName);
        var result = JsonSerializer.Deserialize<JsResult>(resultJson, JsonSerializerOptions.Web);

        if (result is null)
        {
            return BasePrfResult<string>.Fail("Failed to parse registration result");
        }

        if (!result.Success)
        {
            return BasePrfResult<string>.Fail(result.Error ?? "Registration failed");
        }

        return BasePrfResult<string>.Ok(result.CredentialId ?? "");
    }

    public async Task<BasePrfResult<AuthResult>> AuthenticateAsync(
        string credentialIdBase64,
        string saltBase64,
        TimeSpan? cacheTtl = null)
    {
        await EnsureInitializedAsync();

        var ttlMs = cacheTtl.HasValue ? (int?)cacheTtl.Value.TotalMilliseconds : null;
        var resultJson = await BasePrfInterop.AuthenticateAsync(credentialIdBase64, saltBase64, ttlMs);

        return ParseAuthResult(resultJson);
    }

    public async Task<BasePrfResult<AuthResult>> AuthenticateDiscoverableAsync(
        string saltBase64,
        TimeSpan? cacheTtl = null)
    {
        await EnsureInitializedAsync();

        var ttlMs = cacheTtl.HasValue ? (int?)cacheTtl.Value.TotalMilliseconds : null;
        var resultJson = await BasePrfInterop.AuthenticateDiscoverableAsync(saltBase64, ttlMs);

        return ParseAuthResult(resultJson);
    }

    private static BasePrfResult<AuthResult> ParseAuthResult(string resultJson)
    {
        var result = JsonSerializer.Deserialize<JsAuthResult>(resultJson, JsonSerializerOptions.Web);

        if (result is null)
        {
            return BasePrfResult<AuthResult>.Fail("Failed to parse authentication result");
        }

        if (!result.Success)
        {
            return BasePrfResult<AuthResult>.Fail(result.Error ?? "Authentication failed");
        }

        return BasePrfResult<AuthResult>.Ok(new AuthResult(
            result.CredentialId ?? "",
            result.PublicKey ?? ""
        ));
    }

    public bool HasCachedKeys(string saltBase64)
    {
        return BasePrfInterop.HasCachedKeys(saltBase64);
    }

    public AuthResult? GetCachedPublicInfo(string saltBase64)
    {
        var resultJson = BasePrfInterop.GetCachedPublicInfo(saltBase64);
        var result = JsonSerializer.Deserialize<JsAuthResult>(resultJson, JsonSerializerOptions.Web);

        if (result is null || !result.Success)
        {
            return null;
        }

        return new AuthResult(result.CredentialId ?? "", result.PublicKey ?? "");
    }

    public void ClearCachedKeys(string saltBase64)
    {
        BasePrfInterop.ClearCachedKeys(saltBase64);
    }

    public void ClearAllCachedKeys()
    {
        BasePrfInterop.ClearAllCachedKeys();
    }

    public async Task<BasePrfResult<EncryptedData>> EncryptAsync(string plaintext, string saltBase64)
    {
        await EnsureInitializedAsync();

        var plaintextBytes = Encoding.UTF8.GetBytes(plaintext);
        var plaintextBase64 = Convert.ToBase64String(plaintextBytes);

        var resultJson = await BasePrfInterop.EncryptAesGcmAsync(plaintextBase64, saltBase64);
        var result = JsonSerializer.Deserialize<JsEncryptResult>(resultJson, JsonSerializerOptions.Web);

        if (result is null)
        {
            return BasePrfResult<EncryptedData>.Fail("Failed to parse encryption result");
        }

        if (!result.Success)
        {
            return BasePrfResult<EncryptedData>.Fail(result.Error ?? "Encryption failed");
        }

        return BasePrfResult<EncryptedData>.Ok(new EncryptedData(
            result.Ciphertext ?? "",
            result.Nonce ?? ""
        ));
    }

    public async Task<BasePrfResult<string>> DecryptAsync(EncryptedData encrypted, string saltBase64)
    {
        await EnsureInitializedAsync();

        var resultJson = await BasePrfInterop.DecryptAesGcmAsync(
            encrypted.CiphertextBase64,
            encrypted.NonceBase64,
            saltBase64);

        var result = JsonSerializer.Deserialize<JsDecryptResult>(resultJson, JsonSerializerOptions.Web);

        if (result is null)
        {
            return BasePrfResult<string>.Fail("Failed to parse decryption result");
        }

        if (!result.Success)
        {
            return BasePrfResult<string>.Fail(result.Error ?? "Decryption failed");
        }

        var plaintextBytes = Convert.FromBase64String(result.Plaintext ?? "");
        var plaintext = Encoding.UTF8.GetString(plaintextBytes);

        return BasePrfResult<string>.Ok(plaintext);
    }

    public async Task<BasePrfResult<string>> SignAsync(string message, string saltBase64)
    {
        await EnsureInitializedAsync();

        var messageBytes = Encoding.UTF8.GetBytes(message);
        var messageBase64 = Convert.ToBase64String(messageBytes);

        var resultJson = await BasePrfInterop.Ed25519SignAsync(messageBase64, saltBase64);
        var result = JsonSerializer.Deserialize<JsSignResult>(resultJson, JsonSerializerOptions.Web);

        if (result is null)
        {
            return BasePrfResult<string>.Fail("Failed to parse signing result");
        }

        if (!result.Success)
        {
            return BasePrfResult<string>.Fail(result.Error ?? "Signing failed");
        }

        return BasePrfResult<string>.Ok(result.Signature ?? "");
    }

    public async Task<bool> VerifyAsync(string message, string signatureBase64, string publicKeyBase64)
    {
        await EnsureInitializedAsync();

        var messageBytes = Encoding.UTF8.GetBytes(message);
        var messageBase64 = Convert.ToBase64String(messageBytes);

        return await BasePrfInterop.Ed25519VerifyAsync(messageBase64, signatureBase64, publicKeyBase64);
    }

    private async Task EnsureInitializedAsync()
    {
        await BasePrfInterop.EnsureInitializedAsync();

        // Register expiration callback once
        if (!_callbackRegistered)
        {
            BasePrfInterop.SetKeyExpiredCallback(OnKeyExpired);
            _callbackRegistered = true;
        }
    }

    private void OnKeyExpired(string saltBase64)
    {
        KeyExpired?.Invoke(saltBase64);
    }

    // Internal types for JSON deserialization
    private sealed class JsResult
    {
        public bool Success { get; init; }
        public string? Error { get; init; }
        public string? CredentialId { get; init; }
    }

    private sealed class JsAuthResult
    {
        public bool Success { get; init; }
        public string? Error { get; init; }
        public string? CredentialId { get; init; }
        public string? PublicKey { get; init; }
    }

    private sealed class JsEncryptResult
    {
        public bool Success { get; init; }
        public string? Error { get; init; }
        public string? Ciphertext { get; init; }
        public string? Nonce { get; init; }
    }

    private sealed class JsDecryptResult
    {
        public bool Success { get; init; }
        public string? Error { get; init; }
        public string? Plaintext { get; init; }
    }

    private sealed class JsSignResult
    {
        public bool Success { get; init; }
        public string? Error { get; init; }
        public string? Signature { get; init; }
    }
}
