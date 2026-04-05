using BlazorPRF.Crypto.Abstractions.Services;
using System.Diagnostics.CodeAnalysis;
using System.Text.Json;
using BlazorPRF.Api.Json;
using BlazorPRF.Api.Models;
using BlazorPRF.Api.Services;
using BlazorPRF.Crypto.Services;
using BlazorPRF.UI.Models;
using RxBlazorV2.Interface;
using RxBlazorV2.Model;
using RxBlazorV2.MudBlazor.Components;

namespace BlazorPRF.Mail.Models;

/// <summary>
/// Reactive model for admin key management.
/// Commands provide .Executing state for loading indicators.
/// </summary>
[ObservableModelScope(ModelScope.Singleton)]
[ObservableComponent]
public partial class AdminKeyModel : ObservableModel
{
    [SuppressMessage("RxBlazorGenerator", "RXBG050:Partial constructor parameter type may not be registered in DI",
        Justification = "Services registered externally")]
    public partial AdminKeyModel(
        PrfModel prfModel,
        StatusModel statusModel,
        ISignedApiClient signedApiClient,
        ISigningContextProvider signingContextProvider);

    /// <summary>
    /// Registered keys from the backend.
    /// </summary>
    public partial List<RegisteredKey> RegisteredKeys { get; set; } = [];

    // Register form fields
    public partial string NewKeyId { get; set; } = "";
    public partial string NewPublicKey { get; set; } = "";
    public partial string NewUserId { get; set; } = "";

    // Commands
    [ObservableCommand(nameof(LoadKeysAsync))]
    public partial IObservableCommandAsync LoadKeys { get; }

    [ObservableCommand(nameof(RegisterKeyAsync), nameof(CanRegister))]
    public partial IObservableCommandAsync RegisterKey { get; }

    [ObservableCommand(nameof(RevokeKeyAsync))]
    public partial IObservableCommandAsync<string> RevokeKey { get; }

    private bool CanRegister() => !string.IsNullOrWhiteSpace(NewPublicKey);

    private SigningContext CreateSigningContext() => SigningContextProvider.CreateSigningContext();

    private async Task LoadKeysAsync(CancellationToken ct)
    {
        if (!await PrfModel.EnsureKeysAsync())
        {
            StatusModel.AddError("Authentication cancelled or failed");
            return;
        }

        var result = await SignedApiClient.SendAdminSignedAsync("register", "", "GET", CreateSigningContext());
        if (!result.Success || result.Value is null)
        {
            StatusModel.AddError(result.Error ?? "Failed to load keys");
            return;
        }

        var keysResponse = JsonSerializer.Deserialize(result.Value, ApiJsonContext.Default.KeysListResponse);
        if (keysResponse is not null)
        {
            RegisteredKeys = keysResponse.Keys;
        }
    }

    private async Task RegisterKeyAsync(CancellationToken ct)
    {
        if (!await PrfModel.EnsureKeysAsync())
        {
            StatusModel.AddError("Authentication cancelled or failed");
            return;
        }

        var keyId = string.IsNullOrWhiteSpace(NewKeyId) ? NewPublicKey : NewKeyId;
        var body = JsonSerializer.Serialize(new
        {
            keyId,
            publicKey = NewPublicKey,
            userId = NewUserId
        });

        var result = await SignedApiClient.SendAdminSignedAsync("register", body, "POST", CreateSigningContext());
        if (result.Success)
        {
            StatusModel.AddSuccess($"Key registered: {TruncateKey(keyId)}");
            NewKeyId = "";
            NewPublicKey = "";
            NewUserId = "";
            await LoadKeysAsync(ct);
        }
        else
        {
            StatusModel.AddError(result.Error ?? "Failed to register key");
        }
    }

    private async Task RevokeKeyAsync(string keyId, CancellationToken ct)
    {
        if (!await PrfModel.EnsureKeysAsync())
        {
            StatusModel.AddError("Authentication cancelled or failed");
            return;
        }

        var result = await SignedApiClient.SendAdminSignedAsync(
            $"keys?keyId={Uri.EscapeDataString(keyId)}", "", "DELETE", CreateSigningContext());
        if (result.Success)
        {
            StatusModel.AddSuccess($"Key revoked: {TruncateKey(keyId)}");
            await LoadKeysAsync(ct);
        }
        else
        {
            StatusModel.AddError(result.Error ?? "Failed to revoke key");
        }
    }

    public static string TruncateKey(string key)
    {
        if (key.Length <= 20)
        {
            return key;
        }

        return $"{key[..8]}...{key[^8..]}";
    }
}
