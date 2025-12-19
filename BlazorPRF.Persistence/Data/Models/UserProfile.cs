using System.ComponentModel.DataAnnotations;

namespace BlazorPRF.Persistence.Data.Models;

/// <summary>
/// User profile entity with encrypted personal data.
/// Stores username, email, and future SMTP/IMAP configuration.
/// Only one profile record exists per user (singleton pattern).
/// </summary>
public sealed class UserProfile
{
    /// <summary>
    /// Unique identifier.
    /// </summary>
    public Guid Id { get; set; }

    /// <summary>
    /// Encrypted JSON containing user profile data (username, email, SMTP/IMAP settings).
    /// Encrypted with PRF-derived symmetric key.
    /// </summary>
    [MaxLength(8192)]
    public required string EncryptedData { get; set; }

    /// <summary>
    /// When the profile was last updated.
    /// </summary>
    public DateTime UpdatedAt { get; set; }
}
