namespace BlazorPRF.Persistence.Services;

/// <summary>
/// Info about the credential used for encrypting data.
/// </summary>
public sealed record EncryptionCredentialInfo(
    string CredentialId,
    string? Name = null
);

/// <summary>
/// Service to track which credential was used to encrypt data in this database.
/// </summary>
public interface IEncryptionCredentialService
{
    /// <summary>
    /// Gets the credential info that was used to encrypt data, if stored.
    /// </summary>
    Task<EncryptionCredentialInfo?> GetEncryptionCredentialAsync();

    /// <summary>
    /// Sets the credential info used for encryption.
    /// Should be called when first encrypted data is stored.
    /// </summary>
    Task SetEncryptionCredentialAsync(string credentialId, string? name = null);

    /// <summary>
    /// Clears the stored encryption credential info.
    /// </summary>
    Task ClearEncryptionCredentialAsync();
}
