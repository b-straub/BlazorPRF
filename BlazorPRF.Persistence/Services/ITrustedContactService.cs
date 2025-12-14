using BlazorPRF.Persistence.Data.Models;
using BlazorPRF.Shared.Crypto.Models;

namespace BlazorPRF.Persistence.Services;

/// <summary>
/// Service for managing trusted contacts with encrypted user data.
/// Requires authentication to decrypt contact information.
/// </summary>
public interface ITrustedContactService
{
    /// <summary>
    /// Get all trusted contacts. User data is decrypted.
    /// </summary>
    /// <returns>List of contacts with decrypted user data, or empty if decryption fails</returns>
    Task<PrfResult<List<(TrustedContact Contact, ContactUserData UserData)>>> GetAllAsync();

    /// <summary>
    /// Get a trusted contact by ID with decrypted user data.
    /// </summary>
    Task<PrfResult<(TrustedContact Contact, ContactUserData UserData)?>> GetByIdAsync(Guid id);

    /// <summary>
    /// Get a trusted contact by Ed25519 public key.
    /// </summary>
    Task<TrustedContact?> GetByEd25519PublicKeyAsync(string ed25519PublicKey);

    /// <summary>
    /// Create a new trusted contact with encrypted user data.
    /// </summary>
    Task<PrfResult<TrustedContact>> CreateAsync(
        ContactUserData userData,
        string x25519PublicKey,
        string ed25519PublicKey,
        TrustLevel trustLevel,
        TrustDirection direction);

    /// <summary>
    /// Update an existing contact's user data (re-encrypts).
    /// </summary>
    Task<PrfResult<TrustedContact>> UpdateUserDataAsync(Guid id, ContactUserData userData);

    /// <summary>
    /// Update a contact's trust level.
    /// </summary>
    Task<bool> UpdateTrustLevelAsync(Guid id, TrustLevel trustLevel);

    /// <summary>
    /// Delete a trusted contact.
    /// </summary>
    Task<bool> DeleteAsync(Guid id);

    /// <summary>
    /// Check if a contact exists with the given Ed25519 public key.
    /// </summary>
    Task<bool> ExistsByEd25519PublicKeyAsync(string ed25519PublicKey);
}
