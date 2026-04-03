using System.Text.Json;
using BlazorPRF.Api.Services;
using BlazorPRF.Shared.Crypto.Services;
using BlazorPRF.UI.Services;

namespace BlazorPRF.Mail.Services;

/// <summary>
/// Determines user role on the mail relay server via admin/user probe requests.
/// </summary>
public sealed class RelayRegistrationService(
    ISigningContextProvider signingContextProvider,
    ISignedApiClient signedApiClient) : IRelayRegistrationService
{
    public async Task<RegistrationStatus> CheckRegistrationAsync(string ed25519PublicKey)
    {
        try
        {
            // Check if server is reachable and has an admin configured (unauthenticated)
            var setupResult = await signedApiClient.GetAsync("admin-setup");
            if (!setupResult.Success)
            {
                return new RegistrationStatus(PrfUserRole.UNREGISTERED, null);
            }

            var doc = JsonDocument.Parse(setupResult.Value!);
            var serverHasAdmin = doc.RootElement.TryGetProperty("hasAdmin", out var ha) && ha.GetBoolean();

            var context = signingContextProvider.CreateSigningContext();

            // Try admin access first (GET /register lists keys — admin only)
            var adminResult = await signedApiClient.SendAdminSignedAsync("register", "", "GET", context);
            if (adminResult.Success)
            {
                // Auto-register admin's own key as a user so mail operations work
                await EnsureAdminRegisteredAsUserAsync(ed25519PublicKey, context);
                return new RegistrationStatus(PrfUserRole.ADMIN, serverHasAdmin);
            }

            // Not admin — try a user-signed request to check if key is registered
            var userResult = await signedApiClient.SendUserSignedAsync(
                "test_imap",
                JsonSerializer.Serialize(new { imapHost = "", filter = "test" }),
                "POST",
                context);

            // If we get past auth (even with a validation error), the key is registered
            // "IMAP host is required" = registered but bad params
            // "Public key not registered" = not registered
            if (userResult.Success || (userResult.Error is not null && !userResult.Error.Contains("not registered")))
            {
                return new RegistrationStatus(PrfUserRole.USER, serverHasAdmin);
            }

            return new RegistrationStatus(PrfUserRole.UNREGISTERED, serverHasAdmin);
        }
        catch
        {
            // Server unreachable
            return new RegistrationStatus(PrfUserRole.UNREGISTERED, null);
        }
    }

    private async Task EnsureAdminRegisteredAsUserAsync(string ed25519PublicKey, SigningContext context)
    {
        var body = JsonSerializer.Serialize(new
        {
            publicKey = ed25519PublicKey,
            userId = "admin"
        });

        // This is idempotent — if already registered, server just updates
        await signedApiClient.SendAdminSignedAsync("register", body, "POST", context);
    }
}
