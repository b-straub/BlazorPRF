using BlazorPRF.Shared.Formatting;

namespace BlazorPRF.UI.Services;

/// <summary>
/// Stored credential hint with optional metadata.
/// </summary>
public sealed record CredentialHint(
    string CredentialId,
    PublicKeyMetadata? Metadata = null
);

/// <summary>
/// Provides a hint for which credential ID to use for key derivation.
/// This is NOT credential storage - just a reference to the last used credential ID.
/// Implementations can source this from LocalStorage, database, URL parameter, etc.
/// </summary>
public interface ICredentialHintProvider
{
    /// <summary>
    /// Gets the credential hint including metadata.
    /// </summary>
    /// <returns>The credential hint or null if none available.</returns>
    ValueTask<CredentialHint?> GetCredentialHintAsync();

    /// <summary>
    /// Updates the credential hint after successful key derivation.
    /// </summary>
    /// <param name="credentialId">The credential ID to remember.</param>
    /// <param name="metadata">Optional metadata for the public key.</param>
    ValueTask SetCredentialHintAsync(string credentialId, PublicKeyMetadata? metadata = null);

    /// <summary>
    /// Clears the credential hint (e.g., when authentication fails).
    /// </summary>
    ValueTask ClearCredentialHintAsync();
}
