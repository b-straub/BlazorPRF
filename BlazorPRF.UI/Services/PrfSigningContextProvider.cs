using BlazorPRF.Crypto.Abstractions.Services;
using BlazorPRF.Crypto.Services;
using BlazorPRF.UI.Models;

namespace BlazorPRF.UI.Services;

/// <summary>
/// Creates signing contexts from PrfModel authentication state.
/// </summary>
public sealed class PrfSigningContextProvider(PrfModel prfModel, ISigningService signingService)
    : ISigningContextProvider
{
    public SigningContext CreateSigningContext()
    {
        return new SigningContext(
            prfModel.Ed25519PublicKey ?? "",
            prfModel.Salt ?? "",
            async (message, salt) => await signingService.SignAsync(message, salt));
    }
}
