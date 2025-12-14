namespace BlazorPRF.Shared.Crypto.Configuration;

/// <summary>
/// Centralized configuration for key derivation salts and domains.
/// Provides consistent key identifiers across the application.
/// </summary>
public static class KeyDomains
{
    /// <summary>
    /// Default salt used for primary encryption keypair derivation.
    /// </summary>
    public const string DefaultAuthSalt = "my-encryption-keypair";

    /// <summary>
    /// Domain identifier for encrypting contact user data.
    /// </summary>
    public const string ContactsUserData = "contacts-user-data";

    /// <summary>
    /// Domain identifier for invitation email encryption.
    /// </summary>
    public const string InvitationEmail = "invitation-email";

    /// <summary>
    /// Builds a unique key identifier by combining auth salt with domain.
    /// Used for domain-specific key derivation via HKDF.
    /// </summary>
    /// <param name="authSalt">The base authentication salt</param>
    /// <param name="domain">The domain-specific identifier</param>
    /// <returns>Combined key identifier in format "authSalt:domain"</returns>
    public static string GetKeyIdentifier(string authSalt, string domain)
        => $"{authSalt}:{domain}";
}
