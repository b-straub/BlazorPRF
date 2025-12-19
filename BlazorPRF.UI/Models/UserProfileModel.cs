using BlazorPRF.Persistence.Data.Models;
using BlazorPRF.Persistence.Services;
using BlazorPRF.Shared.Crypto.Models;
using RxBlazorV2.Interface;
using RxBlazorV2.Model;
using System.Diagnostics.CodeAnalysis;

namespace BlazorPRF.UI.Models;

/// <summary>
/// Reactive model for user profile state management.
/// Handles loading and saving encrypted profile data.
/// </summary>
[ObservableModelScope(ModelScope.Singleton)]
[ObservableComponent]
public partial class UserProfileModel : ObservableModel
{
    [SuppressMessage("RxBlazorGenerator", "RXBG050:Partial constructor parameter type may not be registered in DI", Justification = "Services registered externally")]
    // ReSharper disable UnusedParameter.Local
    public partial UserProfileModel(PrfModel prfModel, IUserProfileService userProfileService);
    // ReSharper restore UnusedParameter.Local

    /// <summary>
    /// The current user profile data.
    /// </summary>
    public partial UserProfileData? Profile { get; set; }

    /// <summary>
    /// Whether profile is currently loading.
    /// </summary>
    public partial bool Loading { get; set; }

    /// <summary>
    /// Whether profile is currently saving.
    /// </summary>
    public partial bool Saving { get; set; }

    /// <summary>
    /// Error message from last operation.
    /// </summary>
    public partial string? ErrorMessage { get; set; }

    /// <summary>
    /// Success message from last operation.
    /// </summary>
    [ObservableComponentTrigger]
    public partial string? SuccessMessage { get; set; }

    /// <summary>
    /// Whether the profile has been loaded (even if empty).
    /// Components can observe this to know when profile data is ready.
    /// </summary>
    [ObservableComponentTrigger]
    public partial bool ProfileLoaded { get; set; }

    /// <summary>
    /// Whether an error occurred during decryption (wrong passkey).
    /// </summary>
    public partial bool IsDecryptionError { get; set; }

    // Commands
    [ObservableCommand(nameof(LoadProfileAsync))]
    public partial IObservableCommandAsync LoadProfile { get; }

    [ObservableCommand(nameof(SaveProfileAsync))]
    public partial IObservableCommandAsync<UserProfileData> SaveProfile { get; }

    /// <summary>
    /// Load the user profile with decryption.
    /// </summary>
    private async Task LoadProfileAsync()
    {
        Loading = true;
        ErrorMessage = null;
        IsDecryptionError = false;

        try
        {
            // Ensure keys are available (triggers WebAuthn if needed)
            if (!await PrfModel.EnsureKeysAsync())
            {
                ErrorMessage = "Authentication cancelled or failed";
                Loading = false;
                return;
            }

            var result = await UserProfileService.GetAsync();

            if (result.Success)
            {
                Profile = result.Value;
                ProfileLoaded = true;
            }
            else if (result.ErrorCode == PrfErrorCode.DECRYPTION_FAILED ||
                     result.ErrorCode == PrfErrorCode.KEY_DERIVATION_FAILED)
            {
                IsDecryptionError = true;
                ErrorMessage = "Failed to decrypt profile. You may be using a different passkey than the one used to create this data.";
            }
            else
            {
                ErrorMessage = result.Error ?? "Failed to load profile";
            }
        }
        catch (Exception ex)
        {
            ErrorMessage = $"Error: {ex.Message}";
        }
        finally
        {
            Loading = false;
        }
    }

    /// <summary>
    /// Save the user profile with encryption.
    /// </summary>
    private async Task SaveProfileAsync(UserProfileData data)
    {
        Saving = true;
        ErrorMessage = null;
        SuccessMessage = null;

        try
        {
            // Ensure keys are available (triggers WebAuthn if needed)
            if (!await PrfModel.EnsureKeysAsync())
            {
                ErrorMessage = "Authentication cancelled or failed";
                Saving = false;
                return;
            }

            var result = await UserProfileService.SaveAsync(data);

            if (result.Success)
            {
                Profile = result.Value;
                SuccessMessage = "Profile saved successfully!";
            }
            else if (result.ErrorCode == PrfErrorCode.KEY_DERIVATION_FAILED)
            {
                PrfModel.OnKeyDerivationFailed();
                ErrorMessage = "Keys expired. Please try again.";
            }
            else
            {
                ErrorMessage = result.Error ?? "Failed to save profile";
            }
        }
        catch (Exception ex)
        {
            ErrorMessage = $"Error: {ex.Message}";
        }
        finally
        {
            Saving = false;
        }
    }
}
