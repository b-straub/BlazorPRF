using BlazorPRF.Shared.Crypto.Extensions;
using BlazorPRF.Shared.Crypto.Formatting;
using BlazorPRF.Shared.Crypto.Models;
using BlazorPRF.Shared.Crypto.Services;
using RxBlazorV2.Interface;
using RxBlazorV2.Model;
using System.Diagnostics.CodeAnalysis;

namespace BlazorPRF.UI.Models;

/// <summary>
/// Reactive model for invite acceptance panel state management.
/// Handles validation and signing of invite acceptances.
/// </summary>
[ObservableModelScope(ModelScope.Singleton)]
[ObservableComponent]
public partial class InviteAcceptanceModel : ObservableModel
{
    [SuppressMessage("RxBlazorGenerator", "RXBG050:Partial constructor parameter type may not be registered in DI", Justification = "Services registered externally")]
    #pragma warning disable CS9113 // Parameter is unread
    // ReSharper disable UnusedParameter.Local
    public partial InviteAcceptanceModel(PrfModel prfModel, ISigningService signingService);
    // ReSharper restore UnusedParameter.Local
    #pragma warning restore CS9113

    /// <summary>
    /// The raw signed invite input from the user.
    /// </summary>
    [ObservableTrigger(nameof(ValidateInviteAsync))]
    public partial string SignedInviteInput { get; set; } = string.Empty;

    /// <summary>
    /// The user's display name for their public key.
    /// </summary>
    public partial string Username { get; set; } = string.Empty;

    /// <summary>
    /// The accepter's email address (from profile).
    /// </summary>
    public partial string AccepterEmail { get; set; } = string.Empty;

    /// <summary>
    /// Parsed email from the invite code (intended recipient).
    /// </summary>
    public partial string? ParsedEmail { get; set; }

    /// <summary>
    /// Parsed invite code from the signed invite.
    /// </summary>
    public partial string? ParsedInviteCode { get; set; }

    /// <summary>
    /// The inviter's signature from the signed invite.
    /// </summary>
    public partial string? InviterSignature { get; set; }

    /// <summary>
    /// The inviter's Ed25519 public key.
    /// </summary>
    public partial string? InviterEd25519PublicKey { get; set; }

    /// <summary>
    /// The inviter's X25519 public key (for encryption).
    /// </summary>
    public partial string? InviterX25519PublicKey { get; set; }

    /// <summary>
    /// The inviter's display name.
    /// </summary>
    public partial string? InviterUsername { get; set; }

    /// <summary>
    /// The inviter's email address.
    /// </summary>
    public partial string? InviterEmail { get; set; }

    /// <summary>
    /// Whether the invite signature is valid. null = not yet validated.
    /// </summary>
    public partial bool? InviteValid { get; set; }

    /// <summary>
    /// Whether a signing operation is in progress.
    /// </summary>
    public partial bool IsProcessing { get; set; }

    /// <summary>
    /// Error message from the last operation.
    /// </summary>
    public partial string? ErrorMessage { get; set; }

    /// <summary>
    /// The signed response ready to send to the inviter.
    /// </summary>
    public partial string? SignedResponse { get; set; }

    /// <summary>
    /// Whether the invite email matches the accepter's email.
    /// </summary>
    public bool EmailMismatch => ParsedEmail is not null
                                 && !string.IsNullOrWhiteSpace(AccepterEmail)
                                 && !string.Equals(ParsedEmail, AccepterEmail, StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// Whether the user can sign the acceptance.
    /// </summary>
    public bool CanSign => (PrfModel.HasKeys || PrfModel.RequiresOnDemandAuth)
                           && !IsProcessing
                           && InviteValid == true
                           && ParsedEmail is not null
                           && !string.IsNullOrWhiteSpace(Username);

    // Commands
    [ObservableCommand(nameof(SignAcceptanceAsync), nameof(CanSignCheck))]
    public partial IObservableCommandAsync SignAcceptance { get; }

    [ObservableCommand(nameof(ResetImpl))]
    public partial IObservableCommand Reset { get; }

    private bool CanSignCheck() => CanSign;

    /// <summary>
    /// Validates the signed invite input. Called automatically when SignedInviteInput changes.
    /// </summary>
    private async Task ValidateInviteAsync()
    {
        // Reset parsed state
        ParsedEmail = null;
        ParsedInviteCode = null;
        InviterSignature = null;
        InviterEd25519PublicKey = null;
        InviterX25519PublicKey = null;
        InviterUsername = null;
        InviterEmail = null;
        InviteValid = null;
        ErrorMessage = null;

        if (string.IsNullOrWhiteSpace(SignedInviteInput))
        {
            return;
        }

        try
        {
            // UnArmor if armored, otherwise try as raw JSON
            var json = PrfArmor.IsArmoredSignedInvite(SignedInviteInput)
                ? PrfArmor.UnArmorSignedInvite(SignedInviteInput)
                : SignedInviteInput;

            if (json is null)
            {
                InviteValid = false;
                return;
            }

            // Parse the signed invite JSON
            var signedInvite = System.Text.Json.JsonSerializer.Deserialize(json, InviteJsonContext.Default.SignedInvite);

            if (signedInvite is null ||
                string.IsNullOrEmpty(signedInvite.InviteCode) ||
                string.IsNullOrEmpty(signedInvite.InviterSignature) ||
                string.IsNullOrEmpty(signedInvite.InviterEd25519PublicKey) ||
                string.IsNullOrEmpty(signedInvite.InviterX25519PublicKey) ||
                string.IsNullOrEmpty(signedInvite.InviterUsername) ||
                string.IsNullOrEmpty(signedInvite.InviterEmail))
            {
                InviteValid = false;
                return;
            }

            ParsedInviteCode = signedInvite.InviteCode;
            InviterSignature = signedInvite.InviterSignature;
            InviterEd25519PublicKey = signedInvite.InviterEd25519PublicKey;
            InviterX25519PublicKey = signedInvite.InviterX25519PublicKey;
            InviterUsername = signedInvite.InviterUsername;
            InviterEmail = signedInvite.InviterEmail;

            // Extract email from invite code
            var parts = signedInvite.InviteCode.Split('|');
            if (parts.Length == 3 && parts[0].StartsWith("INV-"))
            {
                ParsedEmail = parts[1];
            }
            else
            {
                InviteValid = false;
                return;
            }

            // Verify the inviter's signature
            InviteValid = await SigningService.VerifyAsync(
                signedInvite.InviteCode,
                signedInvite.InviterSignature,
                signedInvite.InviterEd25519PublicKey);
        }
        catch
        {
            InviteValid = false;
        }
    }

    /// <summary>
    /// Signs the acceptance and generates the response.
    /// </summary>
    private async Task SignAcceptanceAsync()
    {
        if (!CanSign)
        {
            ErrorMessage = "Cannot sign: CanSign is false";
            return;
        }

        try
        {
            ArgumentNullException.ThrowIfNull(ParsedEmail);
            ArgumentNullException.ThrowIfNull(ParsedInviteCode);
            ArgumentNullException.ThrowIfNull(InviterEd25519PublicKey);
            ArgumentNullException.ThrowIfNull(InviterX25519PublicKey);
            ArgumentNullException.ThrowIfNull(InviterUsername);
            ArgumentNullException.ThrowIfNull(InviterEmail);
        }
        catch
        {
            ErrorMessage = "Invalid arguments";
            return;
        }

        IsProcessing = true;
        ErrorMessage = null;
        SignedResponse = null;

        try
        {
            // Ensure keys are available (triggers WebAuthn if needed)
            if (!await PrfModel.EnsureKeysAsync())
            {
                ErrorMessage = "Authentication cancelled or failed";
                return;
            }

            var timestamp = DateTimeExtensions.GetUnixSecondsNow();
            var x25519PublicKey = PrfModel.PublicKey;
            var ed25519PublicKey = PrfModel.Ed25519PublicKey;

            if (string.IsNullOrEmpty(x25519PublicKey) || string.IsNullOrEmpty(ed25519PublicKey))
            {
                ErrorMessage = "Keys not available. Please authenticate.";
                return;
            }

            // Build message to sign - include the original signed invite JSON for verification
            // Use AccepterEmail (from profile) so verifier can detect mismatch with invite's target email
            var messageToSign = $"{SignedInviteInput}|{x25519PublicKey}|{ed25519PublicKey}|{Username}|{AccepterEmail}|{timestamp}";

            // Sign the message
            var signResult = await SigningService.SignAsync(messageToSign, PrfModel.Salt);

            if (signResult is { Success: true, Value: not null })
            {
                // Build response using shared DTOs
                // Email field uses AccepterEmail (from profile) so verifier can detect mismatch
                var response = new InviteAcceptanceResponse(
                    new SignedInvite(
                        ParsedInviteCode,
                        InviterSignature,
                        InviterEd25519PublicKey,
                        InviterX25519PublicKey,
                        InviterUsername,
                        InviterEmail),
                    Username,
                    AccepterEmail,
                    x25519PublicKey,
                    ed25519PublicKey,
                    timestamp,
                    messageToSign,
                    signResult.Value);

                var json = System.Text.Json.JsonSerializer.Serialize(response, InviteJsonContext.Default.InviteAcceptanceResponse);
                SignedResponse = PrfArmor.ArmorSignedResponse(json);

                // Notify via reactive model - just set the property
                PrfModel.InviteModel.LastInviteAccepted = new InviteAcceptedEventArgs
                {
                    InviteCode = ParsedInviteCode,
                    InviterEd25519PublicKey = InviterEd25519PublicKey,
                    InviterX25519PublicKey = InviterX25519PublicKey,
                    InviterUsername = InviterUsername,
                    InviterEmail = InviterEmail,
                    Username = Username,
                    Email = AccepterEmail,
                    ArmoredResponse = SignedResponse
                };
            }
            else if (signResult.ErrorCode == PrfErrorCode.KEY_DERIVATION_FAILED)
            {
                PrfModel.OnKeyDerivationFailed();
                ErrorMessage = "Keys expired. Please try again.";
            }
            else
            {
                ErrorMessage = signResult.Error ?? "Signing failed";
            }
        }
        catch (Exception ex)
        {
            ErrorMessage = $"Error: {ex.Message}";
        }
        finally
        {
            IsProcessing = false;
        }
    }

    /// <summary>
    /// Resets the form to initial state (preserves identity from profile).
    /// </summary>
    private void ResetImpl()
    {
        SignedInviteInput = string.Empty;
        // Note: Username and AccepterEmail are preserved (loaded from profile)
        ParsedEmail = null;
        ParsedInviteCode = null;
        InviterSignature = null;
        InviterEd25519PublicKey = null;
        InviterX25519PublicKey = null;
        InviterUsername = null;
        InviterEmail = null;
        InviteValid = null;
        ErrorMessage = null;
        SignedResponse = null;
    }
}
