using System.Runtime.Versioning;
using BlazorPRF.BaseCrypto.Wasm.Services;
using Microsoft.Extensions.DependencyInjection;

namespace BlazorPRF.BaseCrypto.Wasm;

/// <summary>
/// Extension methods for registering BlazorPRF.BaseCrypto.Wasm services.
/// </summary>
public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Adds BlazorPRF.BaseCrypto.Wasm services to the service collection as singleton.
    /// Keys are cached in JavaScript - the service is stateless.
    /// </summary>
    [SupportedOSPlatform("browser")]
    public static IServiceCollection AddBlazorPRFBaseSingleton(this IServiceCollection services)
    {
        services.AddSingleton<IBasePrfService, BasePrfService>();
        return services;
    }

    /// <summary>
    /// Adds BlazorPRF.BaseCrypto.Wasm services to the service collection as scoped.
    /// Keys are cached in JavaScript - the service is stateless.
    /// </summary>
    [SupportedOSPlatform("browser")]
    public static IServiceCollection AddBlazorPRFBaseScoped(this IServiceCollection services)
    {
        services.AddScoped<IBasePrfService, BasePrfService>();
        return services;
    }
}
