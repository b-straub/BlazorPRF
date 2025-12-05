using System.Security.Claims;
using BlazorPRF.UI.Models;
using Microsoft.AspNetCore.Components.Authorization;
using R3;

namespace BlazorPRF.UI.Services;

/// <summary>
/// Authentication state provider based on PRF key derivation.
/// User is considered authenticated when keys have been derived.
/// </summary>
public sealed class PrfAuthenticationStateProvider : AuthenticationStateProvider, IDisposable
{
    private const string HasKeysProperty = "Model.HasKeys";

    private readonly PrfModel _prfModel;
    private readonly AuthenticationState _anonymous = new(new ClaimsPrincipal(new ClaimsIdentity()));
    private readonly IDisposable _subscription;

    public PrfAuthenticationStateProvider(PrfModel prfModel)
    {
        _prfModel = prfModel;

        // Subscribe to model changes to detect authentication state changes
        // Property names are emitted as "Model.PropertyName" by RxBlazorV2
        _subscription = _prfModel.Observable.Subscribe(changedProperties =>
        {
            if (changedProperties.Contains(HasKeysProperty))
            {
                NotifyAuthenticationStateChanged(GetAuthenticationStateAsync());
            }
        });
    }

    public override Task<AuthenticationState> GetAuthenticationStateAsync()
    {
        if (!_prfModel.HasKeys || _prfModel.PublicKey is null)
        {
            return Task.FromResult(_anonymous);
        }

        // Create authenticated identity with public key as identifier
        var claims = new[]
        {
            new Claim(ClaimTypes.NameIdentifier, _prfModel.PublicKey),
            new Claim(ClaimTypes.Name, "PRF User"),
            new Claim("CredentialId", _prfModel.CredentialId ?? string.Empty)
        };

        var identity = new ClaimsIdentity(claims, "PRF");
        var principal = new ClaimsPrincipal(identity);

        return Task.FromResult(new AuthenticationState(principal));
    }

    public void Dispose()
    {
        _subscription.Dispose();
    }
}
