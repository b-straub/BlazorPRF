using BlazorPRF.Api.Services;
using Microsoft.Extensions.DependencyInjection;

namespace BlazorPRF.Api.Extensions;

/// <summary>
/// Extension methods for registering API services.
/// </summary>
public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Adds the signed API client services.
    /// </summary>
    /// <param name="services">Service collection</param>
    /// <param name="httpClientName">Named HTTP client to use (default: "PrfApi")</param>
    /// <returns>Service collection for chaining</returns>
    public static IServiceCollection AddPrfApiClient(
        this IServiceCollection services,
        string httpClientName = "PrfApi")
    {
        services.AddSingleton<ISignedApiClient>(sp =>
        {
            var factory = sp.GetRequiredService<IHttpClientFactory>();
            return new SignedApiClient(factory, httpClientName);
        });

        return services;
    }
}
