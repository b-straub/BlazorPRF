namespace BlazorPRF.Persistence.Data.Models;

/// <summary>
/// User data for a contact. This DTO is encrypted when stored in the database
/// to demonstrate app-level encryption with PRF-derived keys.
/// </summary>
public sealed class ContactUserData
{
    /// <summary>
    /// Display name of the contact.
    /// </summary>
    public required string Username { get; init; }

    /// <summary>
    /// Email address of the contact.
    /// </summary>
    public required string Email { get; init; }

    /// <summary>
    /// Optional comment or notes about the contact.
    /// </summary>
    public string? Comment { get; init; }
}
