using BlazorPRF.Persistence.Services;
using BlazorPRF.Shared.Crypto.Extensions;
using BlazorPRF.Shared.Crypto.Formatting;
using BlazorPRF.Shared.Crypto.Models;
using BlazorPRF.Shared.Crypto.Services;
using RxBlazorV2.Interface;
using RxBlazorV2.Model;
using System.Diagnostics.CodeAnalysis;
using RxBlazorV2.MudBlazor.Components;

namespace BlazorPRF.UI.Models;

/// <summary>
/// Reactive model for invite creation panel state management.
/// Handles profile loading, invite generation, and signing.
/// </summary>
[ObservableModelScope(ModelScope.Singleton)]
[ObservableComponent]
public partial class InviteCreationModel : ObservableModel
{
    [SuppressMessage("RxBlazorGenerator", "RXBG050:Partial constructor parameter type may not be registered in DI", Justification = "Services registered externally")]
    #pragma warning disable CS9113 // Parameter is unread
    // ReSharper disable UnusedParameter.Local
    public partial InviteCreationModel(PrfModel prfModel, InviteModel inviteModel, ISigningService signingService, IUserProfileService userProfileService, StatusModel statusModel);
    // ReSharper restore UnusedParameter.Local
    #pragma warning restore CS9113

    /// <summary>
    /// Whether the user profile is missing or incomplete (no name/email).
    /// </summary>
    public partial bool ProfileMissing { get; set; }

    /// <summary>
    /// The user's display name (from profile).
    /// </summary>
    public partial string MyName { get; set; } = string.Empty;

    /// <summary>
    /// The user's email address (from profile).
    /// </summary>
    public partial string MyEmail { get; set; } = string.Empty;

    /// <summary>
    /// The invitee's email address.
    /// </summary>
    public partial string InviteeEmail { get; set; } = string.Empty;

    /// <summary>
    /// Whether the invitee email is valid.
    /// </summary>
    public partial bool InviteeEmailValid { get; set; }

    /// <summary>
    /// The generated signed invite (armored).
    /// </summary>
    public partial string? SignedInvite { get; set; }

    /// <summary>
    /// Error message from the last operation.
    /// </summary>
    public partial string? ErrorMessage { get; set; }

    /// <summary>
    /// Whether a creation operation is in progress.
    /// </summary>
    public partial bool IsProcessing { get; set; }

    /// <summary>
    /// Whether the user can create an invite.
    /// </summary>
    public bool CanCreate => (PrfModel.HasKeys || PrfModel.RequiresOnDemandAuth)
                             && !IsProcessing
                             && !string.IsNullOrWhiteSpace(MyName)
                             && !string.IsNullOrWhiteSpace(MyEmail)
                             && MyEmail.Contains('@')
                             && InviteeEmailValid;

    // Commands
    [ObservableCommand(nameof(CreateInviteAsync), nameof(CanCreateCheck))]
    public partial IObservableCommandAsync CreateInvite { get; }

    [ObservableCommand(nameof(ResetImpl))]
    public partial IObservableCommand Reset { get; }

    private bool CanCreateCheck() => CanCreate;

    /// <summary>
    /// Loads the user profile and populates MyName/MyEmail.
    /// Sets ProfileMissing if profile is incomplete or absent.
    /// Call this BEFORE opening the dialog.
    /// </summary>
    public async Task LoadProfileAsync()
    {
        ProfileMissing = false;

        if (!PrfModel.HasKeys && !PrfModel.RequiresOnDemandAuth)
        {
            return;
        }

        if (PrfModel.RequiresOnDemandAuth && !PrfModel.HasKeys)
        {
            return;
        }

        var result = await UserProfileService.GetAsync();

        if (result is { Success: true, Value: not null })
        {
            if (string.IsNullOrWhiteSpace(result.Value.Username) ||
                string.IsNullOrWhiteSpace(result.Value.Email))
            {
                ProfileMissing = true;
                return;
            }

            MyName = result.Value.Username;
            MyEmail = result.Value.Email;
        }
        else if (result.Success && result.Value is null)
        {
            ProfileMissing = true;
        }
    }

    /// <summary>
    /// Creates a signed invitation.
    /// </summary>
    private async Task CreateInviteAsync()
    {
        if (!CanCreate)
        {
            return;
        }

        IsProcessing = true;
        ErrorMessage = null;
        SignedInvite = null;

        try
        {
            if (!await PrfModel.EnsureKeysAsync())
            {
                ErrorMessage = "Authentication cancelled or failed";
                return;
            }

            var code = GenerateRandomCode(8);
            var timestamp = DateTimeExtensions.GetUnixSecondsNow();
            var inviteCode = $"INV-{code}|{InviteeEmail}|{timestamp}";

            var ed25519PublicKey = PrfModel.Ed25519PublicKey;
            var x25519PublicKey = PrfModel.PublicKey;

            if (string.IsNullOrEmpty(ed25519PublicKey) || string.IsNullOrEmpty(x25519PublicKey))
            {
                ErrorMessage = "Keys not available. Please authenticate.";
                return;
            }

            var signResult = await SigningService.SignAsync(inviteCode, PrfModel.Salt);

            if (signResult is { Success: true, Value: not null })
            {
                var signedInvite = new SignedInvite(
                    inviteCode,
                    signResult.Value,
                    ed25519PublicKey,
                    x25519PublicKey,
                    MyName,
                    MyEmail);

                var json = System.Text.Json.JsonSerializer.Serialize(signedInvite, InviteJsonContext.Default.SignedInvite);
                SignedInvite = PrfArmor.ArmorSignedInvite(json);

                InviteModel.LastInviteCreated = new InviteCreatedEventArgs
                {
                    InviteCode = inviteCode,
                    Email = InviteeEmail,
                    ArmoredInvite = SignedInvite,
                    InviterEd25519PublicKey = ed25519PublicKey
                };
            }
            else
            {
                ErrorMessage = signResult.Error ?? "Failed to sign invite";
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

    private static string GenerateRandomCode(int length)
    {
        const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        var random = new Random();
        var result = new char[length];
        for (var i = 0; i < length; i++)
        {
            result[i] = chars[random.Next(chars.Length)];
        }
        return new string(result);
    }

    /// <summary>
    /// Resets the form to initial state (preserves identity from profile).
    /// </summary>
    private void ResetImpl()
    {
        InviteeEmail = string.Empty;
        InviteeEmailValid = false;
        SignedInvite = null;
        ErrorMessage = null;
    }
}
