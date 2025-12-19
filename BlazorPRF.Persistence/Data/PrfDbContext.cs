using BlazorPRF.Persistence.Data.Models;
using Microsoft.EntityFrameworkCore;

namespace BlazorPRF.Persistence.Data;

/// <summary>
/// Entity Framework Core DbContext for BlazorPRF persistence layer.
/// Uses SqliteWasmBlazor for browser-based SQLite with OPFS persistence.
/// </summary>
public sealed class PrfDbContext : DbContext
{
    public PrfDbContext(DbContextOptions<PrfDbContext> options) : base(options)
    {
    }

    /// <summary>
    /// Trusted contacts with verified public keys.
    /// </summary>
    public DbSet<TrustedContact> TrustedContacts => Set<TrustedContact>();

    /// <summary>
    /// Invitations sent by the user.
    /// </summary>
    public DbSet<SentInvitation> SentInvitations => Set<SentInvitation>();

    /// <summary>
    /// Invitations received and accepted by the user.
    /// </summary>
    public DbSet<ReceivedInvitation> ReceivedInvitations => Set<ReceivedInvitation>();

    /// <summary>
    /// Application settings (key-value).
    /// </summary>
    public DbSet<AppSetting> AppSettings => Set<AppSetting>();

    /// <summary>
    /// User profile with encrypted personal data.
    /// </summary>
    public DbSet<UserProfile> UserProfiles => Set<UserProfile>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);

        // TrustedContact configuration
        modelBuilder.Entity<TrustedContact>(entity =>
        {
            entity.HasKey(e => e.Id);
            entity.Property(e => e.EncryptedUserData).IsRequired();
            entity.Property(e => e.X25519PublicKey).IsRequired().HasMaxLength(64);
            entity.Property(e => e.Ed25519PublicKey).IsRequired().HasMaxLength(64);
            entity.Property(e => e.TrustLevel).HasConversion<int>();
            entity.Property(e => e.Direction).HasConversion<int>();

            // Index on public keys for lookups
            entity.HasIndex(e => e.Ed25519PublicKey);
            entity.HasIndex(e => e.X25519PublicKey);
        });

        // SentInvitation configuration
        modelBuilder.Entity<SentInvitation>(entity =>
        {
            entity.HasKey(e => e.Id);
            entity.Property(e => e.InviteCode).IsRequired().HasMaxLength(64);
            entity.Property(e => e.EncryptedEmail).IsRequired();
            entity.Property(e => e.ArmoredInvite).IsRequired();
            entity.Property(e => e.Status).HasConversion<int>();

            // Index on invite code for lookups
            entity.HasIndex(e => e.InviteCode);

            // Relationship to TrustedContact
            entity.HasOne(e => e.TrustedContact)
                  .WithMany()
                  .HasForeignKey(e => e.TrustedContactId)
                  .OnDelete(DeleteBehavior.SetNull);
        });

        // ReceivedInvitation configuration
        modelBuilder.Entity<ReceivedInvitation>(entity =>
        {
            entity.HasKey(e => e.Id);
            entity.Property(e => e.InviteCode).IsRequired().HasMaxLength(64);
            entity.Property(e => e.InviterEd25519PublicKey).IsRequired().HasMaxLength(64);

            // Index on inviter public key
            entity.HasIndex(e => e.InviterEd25519PublicKey);

            // Relationship to TrustedContact
            entity.HasOne(e => e.TrustedContact)
                  .WithMany()
                  .HasForeignKey(e => e.TrustedContactId)
                  .OnDelete(DeleteBehavior.SetNull);
        });

        // AppSetting configuration
        modelBuilder.Entity<AppSetting>(entity =>
        {
            entity.HasKey(e => e.Key);
            entity.Property(e => e.Key).HasMaxLength(128);
            entity.Property(e => e.Value).IsRequired();
        });

        // UserProfile configuration
        modelBuilder.Entity<UserProfile>(entity =>
        {
            entity.HasKey(e => e.Id);
            entity.Property(e => e.EncryptedData).IsRequired();
        });
    }
}
