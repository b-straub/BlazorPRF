using System.Text.Json;
using BlazorPRF.Persistence.Data;
using BlazorPRF.Persistence.Data.Models;
using BlazorPRF.Persistence.Json;
using BlazorPRF.Shared.Crypto.Configuration;
using BlazorPRF.Shared.Crypto.Models;
using BlazorPRF.Shared.Crypto.Services;
using Microsoft.EntityFrameworkCore;

namespace BlazorPRF.Persistence.Services;

/// <summary>
/// Service for managing the user's encrypted profile data.
/// Only one profile record exists per user (singleton pattern).
/// Follows TrustedContactService pattern for encrypted storage.
/// </summary>
public sealed class UserProfileService : IUserProfileService
{
    private readonly IDbContextFactory<PrfDbContext> _dbContextFactory;
    private readonly ISymmetricEncryption _symmetricEncryption;

    /// <summary>
    /// Key identifier for symmetric encryption of user profile data.
    /// Uses centralized KeyDomains constants for consistency.
    /// </summary>
    private static string ProfileEncryptionKey =>
        KeyDomains.GetKeyIdentifier(KeyDomains.DefaultAuthSalt, KeyDomains.UserProfileData);

    public UserProfileService(
        IDbContextFactory<PrfDbContext> dbContextFactory,
        ISymmetricEncryption symmetricEncryption)
    {
        _dbContextFactory = dbContextFactory;
        _symmetricEncryption = symmetricEncryption;
    }

    public async Task<PrfResult<UserProfileData?>> GetAsync()
    {
        await using var db = await _dbContextFactory.CreateDbContextAsync();
        // SingleOrDefaultAsync is semantically correct since only one profile exists per user
        var profile = await db.UserProfiles.SingleOrDefaultAsync();

        if (profile is null)
        {
            return PrfResult<UserProfileData?>.Ok(null);
        }

        var decryptedResult = await DecryptProfileDataAsync(profile.EncryptedData);
        if (!decryptedResult.Success)
        {
            return PrfResult<UserProfileData?>.Fail(
                decryptedResult.ErrorCode ?? PrfErrorCode.DECRYPTION_FAILED);
        }

        return PrfResult<UserProfileData?>.Ok(decryptedResult.Value);
    }

    public async Task<PrfResult<UserProfileData>> SaveAsync(UserProfileData data)
    {
        var encryptedResult = await EncryptProfileDataAsync(data);
        if (!encryptedResult.Success || encryptedResult.Value is null)
        {
            return PrfResult<UserProfileData>.Fail(
                encryptedResult.ErrorCode ?? PrfErrorCode.ENCRYPTION_FAILED);
        }

        await using var db = await _dbContextFactory.CreateDbContextAsync();
        var existingProfile = await db.UserProfiles.SingleOrDefaultAsync();

        if (existingProfile is null)
        {
            // Create new profile
            var profile = new UserProfile
            {
                Id = Guid.NewGuid(),
                EncryptedData = encryptedResult.Value,
                UpdatedAt = DateTime.UtcNow
            };
            await db.UserProfiles.AddAsync(profile);
        }
        else
        {
            // Update existing profile
            existingProfile.EncryptedData = encryptedResult.Value;
            existingProfile.UpdatedAt = DateTime.UtcNow;
        }

        await db.SaveChangesAsync();
        return PrfResult<UserProfileData>.Ok(data);
    }

    public async Task<bool> ExistsAsync()
    {
        await using var db = await _dbContextFactory.CreateDbContextAsync();
        return await db.UserProfiles.AnyAsync();
    }

    /// <summary>
    /// Encrypt profile data to JSON string using PRF-derived symmetric key.
    /// </summary>
    private async Task<PrfResult<string>> EncryptProfileDataAsync(UserProfileData data)
    {
        var json = JsonSerializer.Serialize(data, PersistenceJsonContext.Default.UserProfileData);
        var encryptedResult = await _symmetricEncryption.EncryptAsync(json, ProfileEncryptionKey);

        if (!encryptedResult.Success || encryptedResult.Value is null)
        {
            return PrfResult<string>.Fail(encryptedResult.ErrorCode ?? PrfErrorCode.ENCRYPTION_FAILED);
        }

        // Store as JSON for simplicity
        var encryptedJson = JsonSerializer.Serialize(encryptedResult.Value, PersistenceJsonContext.Default.SymmetricEncryptedMessage);
        return PrfResult<string>.Ok(encryptedJson);
    }

    /// <summary>
    /// Decrypt profile data from encrypted JSON string.
    /// </summary>
    private async Task<PrfResult<UserProfileData>> DecryptProfileDataAsync(string encryptedData)
    {
        SymmetricEncryptedMessage? encrypted;
        try
        {
            encrypted = JsonSerializer.Deserialize(encryptedData, PersistenceJsonContext.Default.SymmetricEncryptedMessage);
        }
        catch (JsonException)
        {
            return PrfResult<UserProfileData>.Fail(PrfErrorCode.DECRYPTION_FAILED);
        }

        if (encrypted is null)
        {
            return PrfResult<UserProfileData>.Fail(PrfErrorCode.DECRYPTION_FAILED);
        }

        var decryptedResult = await _symmetricEncryption.DecryptAsync(encrypted, ProfileEncryptionKey);

        if (!decryptedResult.Success || decryptedResult.Value is null)
        {
            return PrfResult<UserProfileData>.Fail(decryptedResult.ErrorCode ?? PrfErrorCode.DECRYPTION_FAILED);
        }

        UserProfileData? profileData;
        try
        {
            profileData = JsonSerializer.Deserialize(decryptedResult.Value, PersistenceJsonContext.Default.UserProfileData);
        }
        catch (JsonException)
        {
            return PrfResult<UserProfileData>.Fail(PrfErrorCode.DECRYPTION_FAILED);
        }

        if (profileData is null)
        {
            return PrfResult<UserProfileData>.Fail(PrfErrorCode.DECRYPTION_FAILED);
        }

        return PrfResult<UserProfileData>.Ok(profileData);
    }
}
