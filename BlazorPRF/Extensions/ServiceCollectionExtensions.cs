using System.Runtime.Versioning;
using BlazorPRF.Configuration;
using BlazorPRF.Services;
using BlazorPRF.Shared.Services;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace BlazorPRF.Extensions;

/// <summary>
/// Extension methods for registering BlazorPRF services.
/// </summary>
[SupportedOSPlatform("browser")]
public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Add BlazorPRF services to the service collection.
    /// </summary>
    /// <param name="services">The service collection</param>
    /// <param name="configuration">Optional configuration for binding options</param>
    /// <returns>The service collection for chaining</returns>
    public static IServiceCollection AddBlazorPrf(
        this IServiceCollection services,
        IConfiguration? configuration = null)
    {
        // Configure options
        if (configuration is not null)
        {
            services.Configure<PrfOptions>(configuration.GetSection(PrfOptions.SectionName));
            services.Configure<KeyCacheOptions>(configuration.GetSection(KeyCacheOptions.SectionName));
        }
        else
        {
            // Use default options
            services.Configure<PrfOptions>(_ => { });
            services.Configure<KeyCacheOptions>(_ => { });
        }

        // Register services
        services.AddSingleton<ISecureKeyCache, SecureKeyCache>();
        services.AddSingleton<PrfService>();
        services.AddSingleton<IPrfService>(sp => sp.GetRequiredService<PrfService>());
        services.AddSingleton<IEd25519PublicKeyProvider>(sp => sp.GetRequiredService<PrfService>());
        services.AddSingleton<ISymmetricEncryption, SymmetricEncryptionService>();
        services.AddSingleton<IAsymmetricEncryption, AsymmetricEncryptionService>();
        services.AddSingleton<ISigningService, SigningService>();

        return services;
    }

    /// <summary>
    /// Add BlazorPRF services with custom configuration.
    /// </summary>
    /// <param name="services">The service collection</param>
    /// <param name="configurePrf">Action to configure PRF options</param>
    /// <param name="configureCache">Optional action to configure cache options</param>
    /// <returns>The service collection for chaining</returns>
    public static IServiceCollection AddBlazorPrf(
        this IServiceCollection services,
        Action<PrfOptions> configurePrf,
        Action<KeyCacheOptions>? configureCache = null)
    {
        services.Configure(configurePrf);
        services.Configure(configureCache ?? (_ => { }));

        // Register services
        services.AddScoped<ISecureKeyCache, SecureKeyCache>();
        services.AddScoped<PrfService>();
        services.AddScoped<IPrfService>(sp => sp.GetRequiredService<PrfService>());
        services.AddScoped<IEd25519PublicKeyProvider>(sp => sp.GetRequiredService<PrfService>());
        services.AddScoped<ISymmetricEncryption, SymmetricEncryptionService>();
        services.AddScoped<IAsymmetricEncryption, AsymmetricEncryptionService>();
        services.AddScoped<ISigningService, SigningService>();

        return services;
    }
}
