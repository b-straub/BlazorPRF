using System.Text.Json;
using BlazorPRF.Persistence.Data;
using BlazorPRF.Persistence.Data.Models;
using BlazorPRF.Shared.Crypto.Configuration;
using BlazorPRF.Shared.Crypto.Models;
using BlazorPRF.Shared.Crypto.Services;
using Microsoft.EntityFrameworkCore;

namespace BlazorPRF.Persistence.Services;

/// <summary>
/// Service for managing sent and received invitations.
/// Email addresses in sent invitations are encrypted.
/// </summary>
public sealed class InvitationService : IInvitationService
{
    private readonly IDbContextFactory<PrfDbContext> _dbContextFactory;
    private readonly ISymmetricEncryption _symmetricEncryption;

    /// <summary>
    /// Key identifier for symmetric encryption of invitation emails.
    /// Uses centralized KeyDomains constants for consistency.
    /// </summary>
    private static string InvitationEncryptionKey =>
        KeyDomains.GetKeyIdentifier(KeyDomains.DefaultAuthSalt, KeyDomains.InvitationEmail);

    public InvitationService(
        IDbContextFactory<PrfDbContext> dbContextFactory,
        ISymmetricEncryption symmetricEncryption)
    {
        _dbContextFactory = dbContextFactory;
        _symmetricEncryption = symmetricEncryption;
    }

    // Sent invitations

    /// <inheritdoc />
    public async Task<PrfResult<List<(SentInvitation Invitation, string? Email)>>> GetSentInvitationsAsync()
    {
        await using var db = await _dbContextFactory.CreateDbContextAsync();
        var invitations = await db.SentInvitations
            .Include(i => i.TrustedContact)
            .OrderByDescending(i => i.CreatedAt)
            .ToListAsync();

        var results = new List<(SentInvitation, string?)>();

        foreach (var invitation in invitations)
        {
            var emailResult = await DecryptEmailAsync(invitation.EncryptedEmail);
            // If decryption fails, include invitation with null email
            results.Add((invitation, emailResult.Success ? emailResult.Value : null));
        }

        return PrfResult<List<(SentInvitation, string?)>>.Ok(results);
    }

    /// <inheritdoc />
    public async Task<PrfResult<SentInvitation>> CreateSentInvitationAsync(
        string inviteCode,
        string email,
        string armoredInvite)
    {
        var encryptedEmailResult = await EncryptEmailAsync(email);
        if (!encryptedEmailResult.Success || encryptedEmailResult.Value is null)
        {
            return PrfResult<SentInvitation>.Fail(
                encryptedEmailResult.ErrorCode ?? PrfErrorCode.EncryptionFailed);
        }

        var invitation = new SentInvitation
        {
            Id = Guid.NewGuid(),
            InviteCode = inviteCode,
            EncryptedEmail = encryptedEmailResult.Value,
            ArmoredInvite = armoredInvite,
            Status = InviteStatus.Pending,
            CreatedAt = DateTime.UtcNow
        };

        await using var db = await _dbContextFactory.CreateDbContextAsync();
        await db.SentInvitations.AddAsync(invitation);
        await db.SaveChangesAsync();

        return PrfResult<SentInvitation>.Ok(invitation);
    }

    /// <inheritdoc />
    public async Task<bool> MarkSentInvitationAcceptedAsync(string inviteCode, Guid trustedContactId)
    {
        await using var db = await _dbContextFactory.CreateDbContextAsync();
        var invitation = await db.SentInvitations
            .FirstOrDefaultAsync(i => i.InviteCode == inviteCode);

        if (invitation is null)
        {
            return false;
        }

        invitation.Status = InviteStatus.Accepted;
        invitation.AcceptedAt = DateTime.UtcNow;
        invitation.TrustedContactId = trustedContactId;
        await db.SaveChangesAsync();

        return true;
    }

    /// <inheritdoc />
    public async Task<bool> UpdateSentInvitationStatusAsync(Guid id, InviteStatus status)
    {
        await using var db = await _dbContextFactory.CreateDbContextAsync();
        var invitation = await db.SentInvitations.FindAsync(id);

        if (invitation is null)
        {
            return false;
        }

        invitation.Status = status;
        await db.SaveChangesAsync();

        return true;
    }

    /// <inheritdoc />
    public async Task<bool> DeleteSentInvitationAsync(Guid id)
    {
        await using var db = await _dbContextFactory.CreateDbContextAsync();
        var invitation = await db.SentInvitations.FindAsync(id);

        if (invitation is null)
        {
            return false;
        }

        db.SentInvitations.Remove(invitation);
        await db.SaveChangesAsync();

        return true;
    }

    /// <inheritdoc />
    public async Task<SentInvitation?> GetSentInvitationByCodeAsync(string inviteCode)
    {
        await using var db = await _dbContextFactory.CreateDbContextAsync();
        return await db.SentInvitations
            .Include(i => i.TrustedContact)
            .FirstOrDefaultAsync(i => i.InviteCode == inviteCode);
    }

    // Received invitations

    /// <inheritdoc />
    public async Task<List<ReceivedInvitation>> GetReceivedInvitationsAsync()
    {
        await using var db = await _dbContextFactory.CreateDbContextAsync();
        return await db.ReceivedInvitations
            .Include(i => i.TrustedContact)
            .OrderByDescending(i => i.AcceptedAt)
            .ToListAsync();
    }

    /// <inheritdoc />
    public async Task<ReceivedInvitation> CreateReceivedInvitationAsync(
        string inviteCode,
        string inviterEd25519PublicKey,
        Guid? trustedContactId = null)
    {
        var invitation = new ReceivedInvitation
        {
            Id = Guid.NewGuid(),
            InviteCode = inviteCode,
            InviterEd25519PublicKey = inviterEd25519PublicKey,
            AcceptedAt = DateTime.UtcNow,
            TrustedContactId = trustedContactId
        };

        await using var db = await _dbContextFactory.CreateDbContextAsync();
        await db.ReceivedInvitations.AddAsync(invitation);
        await db.SaveChangesAsync();

        return invitation;
    }

    /// <inheritdoc />
    public async Task<bool> LinkReceivedInvitationToContactAsync(Guid invitationId, Guid trustedContactId)
    {
        await using var db = await _dbContextFactory.CreateDbContextAsync();
        var invitation = await db.ReceivedInvitations.FindAsync(invitationId);

        if (invitation is null)
        {
            return false;
        }

        invitation.TrustedContactId = trustedContactId;
        await db.SaveChangesAsync();

        return true;
    }

    /// <inheritdoc />
    public async Task<bool> ReceivedInvitationExistsAsync(string inviteCode)
    {
        await using var db = await _dbContextFactory.CreateDbContextAsync();
        return await db.ReceivedInvitations
            .AnyAsync(i => i.InviteCode == inviteCode);
    }

    /// <summary>
    /// Encrypt email address using PRF-derived symmetric key.
    /// </summary>
    private async Task<PrfResult<string>> EncryptEmailAsync(string email)
    {
        var encryptedResult = await _symmetricEncryption.EncryptAsync(email, InvitationEncryptionKey);

        if (!encryptedResult.Success || encryptedResult.Value is null)
        {
            return PrfResult<string>.Fail(encryptedResult.ErrorCode ?? PrfErrorCode.EncryptionFailed);
        }

        var encryptedJson = JsonSerializer.Serialize(encryptedResult.Value);
        return PrfResult<string>.Ok(encryptedJson);
    }

    /// <summary>
    /// Decrypt email address from encrypted JSON string.
    /// </summary>
    private async Task<PrfResult<string>> DecryptEmailAsync(string encryptedEmail)
    {
        SymmetricEncryptedMessage? encrypted;
        try
        {
            encrypted = JsonSerializer.Deserialize<SymmetricEncryptedMessage>(encryptedEmail);
        }
        catch (JsonException)
        {
            return PrfResult<string>.Fail(PrfErrorCode.DecryptionFailed);
        }

        if (encrypted is null)
        {
            return PrfResult<string>.Fail(PrfErrorCode.DecryptionFailed);
        }

        return await _symmetricEncryption.DecryptAsync(encrypted, InvitationEncryptionKey);
    }
}
