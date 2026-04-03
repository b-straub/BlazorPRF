using BlazorPRF.UI.Services;

namespace BlazorPRF.Mail.Services;

/// <summary>
/// Result of checking relay registration status.
/// </summary>
public sealed record RegistrationStatus(PrfUserRole Role, bool? ServerHasAdmin);

/// <summary>
/// Determines user role on the mail relay server.
/// </summary>
public interface IRelayRegistrationService
{
    /// <summary>
    /// Check admin/user registration status on the relay server.
    /// </summary>
    /// <param name="ed25519PublicKey">User's Ed25519 public key</param>
    Task<RegistrationStatus> CheckRegistrationAsync(string ed25519PublicKey);
}
