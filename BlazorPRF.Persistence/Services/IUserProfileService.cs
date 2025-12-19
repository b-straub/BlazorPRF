using BlazorPRF.Persistence.Data.Models;
using BlazorPRF.Shared.Crypto.Models;

namespace BlazorPRF.Persistence.Services;

/// <summary>
/// Service for managing the user's encrypted profile data.
/// Requires authentication to decrypt profile information.
/// Only one profile record exists per user (singleton pattern).
/// </summary>
public interface IUserProfileService
{
    /// <summary>
    /// Get the user's profile with decrypted data.
    /// </summary>
    /// <returns>Profile data if exists and decryption succeeds, null if no profile, or error if decryption fails</returns>
    Task<PrfResult<UserProfileData?>> GetAsync();

    /// <summary>
    /// Save the user's profile (creates or updates).
    /// Data is encrypted before storage.
    /// </summary>
    /// <param name="data">Profile data to encrypt and save.</param>
    /// <returns>The saved profile data, or error if encryption fails.</returns>
    Task<PrfResult<UserProfileData>> SaveAsync(UserProfileData data);

    /// <summary>
    /// Check if a profile exists (without requiring decryption).
    /// </summary>
    Task<bool> ExistsAsync();
}
