using System.Runtime.Versioning;
using BlazorPRF.Wasm.Crypto.Services;
using Microsoft.Extensions.DependencyInjection;

namespace BlazorPRF.Wasm.Crypto;

/// <summary>
/// Extension methods for registering BlazorPRF.Wasm.Crypto services.
/// </summary>
public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Adds BlazorPRF.Wasm.Crypto services to the service collection as singleton.
    /// Keys are cached in JavaScript - the service is stateless.
    /// </summary>
    [SupportedOSPlatform("browser")]
    public static IServiceCollection AddBlazorPRFWasmSingleton(this IServiceCollection services)
    {
        services.AddSingleton<IBasePrfService, BasePrfService>();
        return services;
    }

    /// <summary>
    /// Adds BlazorPRF.Wasm.Crypto services to the service collection as scoped.
    /// Keys are cached in JavaScript - the service is stateless.
    /// </summary>
    [SupportedOSPlatform("browser")]
    public static IServiceCollection AddBlazorPRFWasmScoped(this IServiceCollection services)
    {
        services.AddScoped<IBasePrfService, BasePrfService>();
        return services;
    }
}
