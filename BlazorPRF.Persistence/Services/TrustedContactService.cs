using System.Text.Json;
using BlazorPRF.Persistence.Data;
using BlazorPRF.Persistence.Data.Models;
using BlazorPRF.Shared.Crypto.Configuration;
using BlazorPRF.Shared.Crypto.Models;
using BlazorPRF.Shared.Crypto.Services;
using Microsoft.EntityFrameworkCore;

namespace BlazorPRF.Persistence.Services;

/// <summary>
/// Service for managing trusted contacts with app-level encryption of user data.
/// Demonstrates encrypting sensitive data using PRF-derived symmetric keys.
/// </summary>
public sealed class TrustedContactService : ITrustedContactService
{
    private readonly IDbContextFactory<PrfDbContext> _dbContextFactory;
    private readonly ISymmetricEncryption _symmetricEncryption;
    private readonly IEncryptionCredentialService _encryptionCredentialService;

    /// <summary>
    /// Key identifier for symmetric encryption of contact user data.
    /// Uses centralized KeyDomains constants for consistency.
    /// </summary>
    private static string ContactsEncryptionKey =>
        KeyDomains.GetKeyIdentifier(KeyDomains.DefaultAuthSalt, KeyDomains.ContactsUserData);

    public TrustedContactService(
        IDbContextFactory<PrfDbContext> dbContextFactory,
        ISymmetricEncryption symmetricEncryption,
        IEncryptionCredentialService encryptionCredentialService)
    {
        _dbContextFactory = dbContextFactory;
        _symmetricEncryption = symmetricEncryption;
        _encryptionCredentialService = encryptionCredentialService;
    }

    /// <inheritdoc />
    public async Task<PrfResult<List<(TrustedContact Contact, ContactUserData UserData)>>> GetAllAsync()
    {
        await using var db = await _dbContextFactory.CreateDbContextAsync();
        var contacts = await db.TrustedContacts
            .OrderByDescending(c => c.CreatedAt)
            .ToListAsync();

        var results = new List<(TrustedContact, ContactUserData)>();

        foreach (var contact in contacts)
        {
            var userDataResult = await DecryptUserDataAsync(contact.EncryptedUserData);
            if (!userDataResult.Success || userDataResult.Value is null)
            {
                // Return error if any decryption fails (user not authenticated)
                return PrfResult<List<(TrustedContact, ContactUserData)>>.Fail(
                    userDataResult.ErrorCode ?? PrfErrorCode.DecryptionFailed);
            }

            results.Add((contact, userDataResult.Value));
        }

        return PrfResult<List<(TrustedContact, ContactUserData)>>.Ok(results);
    }

    /// <inheritdoc />
    public async Task<PrfResult<(TrustedContact Contact, ContactUserData UserData)?>> GetByIdAsync(Guid id)
    {
        await using var db = await _dbContextFactory.CreateDbContextAsync();
        var contact = await db.TrustedContacts.FindAsync(id);

        if (contact is null)
        {
            return PrfResult<(TrustedContact, ContactUserData)?>.Ok(null);
        }

        var userDataResult = await DecryptUserDataAsync(contact.EncryptedUserData);
        if (!userDataResult.Success || userDataResult.Value is null)
        {
            return PrfResult<(TrustedContact, ContactUserData)?>.Fail(
                userDataResult.ErrorCode ?? PrfErrorCode.DecryptionFailed);
        }

        return PrfResult<(TrustedContact, ContactUserData)?>.Ok((contact, userDataResult.Value));
    }

    /// <inheritdoc />
    public async Task<TrustedContact?> GetByEd25519PublicKeyAsync(string ed25519PublicKey)
    {
        await using var db = await _dbContextFactory.CreateDbContextAsync();
        return await db.TrustedContacts
            .FirstOrDefaultAsync(c => c.Ed25519PublicKey == ed25519PublicKey);
    }

    /// <inheritdoc />
    public async Task<PrfResult<TrustedContact>> CreateAsync(
        ContactUserData userData,
        string x25519PublicKey,
        string ed25519PublicKey,
        TrustLevel trustLevel,
        TrustDirection direction,
        string? encryptingCredentialId = null,
        string? encryptingCredentialName = null)
    {
        var encryptedResult = await EncryptUserDataAsync(userData);
        if (!encryptedResult.Success || encryptedResult.Value is null)
        {
            return PrfResult<TrustedContact>.Fail(
                encryptedResult.ErrorCode ?? PrfErrorCode.EncryptionFailed);
        }

        var contact = new TrustedContact
        {
            Id = Guid.NewGuid(),
            EncryptedUserData = encryptedResult.Value,
            X25519PublicKey = x25519PublicKey,
            Ed25519PublicKey = ed25519PublicKey,
            TrustLevel = trustLevel,
            Direction = direction,
            VerifiedAt = DateTime.UtcNow,
            CreatedAt = DateTime.UtcNow
        };

        await using var db = await _dbContextFactory.CreateDbContextAsync();
        await db.TrustedContacts.AddAsync(contact);
        await db.SaveChangesAsync();

        // Track which credential encrypted the data (if not already tracked)
        if (!string.IsNullOrWhiteSpace(encryptingCredentialId))
        {
            var existingCredential = await _encryptionCredentialService.GetEncryptionCredentialAsync();
            if (existingCredential is null)
            {
                await _encryptionCredentialService.SetEncryptionCredentialAsync(
                    encryptingCredentialId, encryptingCredentialName);
            }
        }

        return PrfResult<TrustedContact>.Ok(contact);
    }

    /// <inheritdoc />
    public async Task<PrfResult<TrustedContact>> UpdateUserDataAsync(Guid id, ContactUserData userData)
    {
        await using var db = await _dbContextFactory.CreateDbContextAsync();
        var contact = await db.TrustedContacts.FindAsync(id);

        if (contact is null)
        {
            return PrfResult<TrustedContact>.Fail(PrfErrorCode.CredentialNotFound);
        }

        var encryptedResult = await EncryptUserDataAsync(userData);
        if (!encryptedResult.Success || encryptedResult.Value is null)
        {
            return PrfResult<TrustedContact>.Fail(
                encryptedResult.ErrorCode ?? PrfErrorCode.EncryptionFailed);
        }

        contact.EncryptedUserData = encryptedResult.Value;
        await db.SaveChangesAsync();

        return PrfResult<TrustedContact>.Ok(contact);
    }

    /// <inheritdoc />
    public async Task<bool> UpdateTrustLevelAsync(Guid id, TrustLevel trustLevel)
    {
        await using var db = await _dbContextFactory.CreateDbContextAsync();
        var contact = await db.TrustedContacts.FindAsync(id);

        if (contact is null)
        {
            return false;
        }

        contact.TrustLevel = trustLevel;
        await db.SaveChangesAsync();
        return true;
    }

    /// <inheritdoc />
    public async Task<bool> DeleteAsync(Guid id)
    {
        await using var db = await _dbContextFactory.CreateDbContextAsync();
        var contact = await db.TrustedContacts.FindAsync(id);

        if (contact is null)
        {
            return false;
        }

        db.TrustedContacts.Remove(contact);
        await db.SaveChangesAsync();
        return true;
    }

    /// <inheritdoc />
    public async Task<bool> ExistsByEd25519PublicKeyAsync(string ed25519PublicKey)
    {
        await using var db = await _dbContextFactory.CreateDbContextAsync();
        return await db.TrustedContacts
            .AnyAsync(c => c.Ed25519PublicKey == ed25519PublicKey);
    }

    /// <summary>
    /// Encrypt user data to JSON string using PRF-derived symmetric key.
    /// </summary>
    private async Task<PrfResult<string>> EncryptUserDataAsync(ContactUserData userData)
    {
        var json = JsonSerializer.Serialize(userData);
        var encryptedResult = await _symmetricEncryption.EncryptAsync(json, ContactsEncryptionKey);

        if (!encryptedResult.Success || encryptedResult.Value is null)
        {
            return PrfResult<string>.Fail(encryptedResult.ErrorCode ?? PrfErrorCode.EncryptionFailed);
        }

        // Store as JSON for simplicity (could use binary format for efficiency)
        var encryptedJson = JsonSerializer.Serialize(encryptedResult.Value);
        return PrfResult<string>.Ok(encryptedJson);
    }

    /// <summary>
    /// Decrypt user data from encrypted JSON string.
    /// </summary>
    private async Task<PrfResult<ContactUserData>> DecryptUserDataAsync(string encryptedUserData)
    {
        SymmetricEncryptedMessage? encrypted;
        try
        {
            encrypted = JsonSerializer.Deserialize<SymmetricEncryptedMessage>(encryptedUserData);
        }
        catch (JsonException)
        {
            return PrfResult<ContactUserData>.Fail(PrfErrorCode.DecryptionFailed);
        }

        if (encrypted is null)
        {
            return PrfResult<ContactUserData>.Fail(PrfErrorCode.DecryptionFailed);
        }

        var decryptedResult = await _symmetricEncryption.DecryptAsync(encrypted, ContactsEncryptionKey);

        if (!decryptedResult.Success || decryptedResult.Value is null)
        {
            return PrfResult<ContactUserData>.Fail(decryptedResult.ErrorCode ?? PrfErrorCode.DecryptionFailed);
        }

        ContactUserData? userData;
        try
        {
            userData = JsonSerializer.Deserialize<ContactUserData>(decryptedResult.Value);
        }
        catch (JsonException)
        {
            return PrfResult<ContactUserData>.Fail(PrfErrorCode.DecryptionFailed);
        }

        if (userData is null)
        {
            return PrfResult<ContactUserData>.Fail(PrfErrorCode.DecryptionFailed);
        }

        return PrfResult<ContactUserData>.Ok(userData);
    }
}
