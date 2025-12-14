namespace BlazorPRF.BaseCrypto.Wasm.Models;

/// <summary>
/// AES-GCM encrypted data.
/// </summary>
/// <param name="CiphertextBase64">Base64-encoded ciphertext (includes authentication tag)</param>
/// <param name="NonceBase64">Base64-encoded 12-byte nonce</param>
public sealed record EncryptedData(
    string CiphertextBase64,
    string NonceBase64
);
