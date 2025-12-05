using BlazorPRF.Shared.Services;
using Microsoft.Extensions.DependencyInjection;
using PseudoPRF.Services;

namespace PseudoPRF.Extensions;

/// <summary>
/// Extension methods for registering PseudoPRF services.
/// </summary>
public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Adds PseudoPRF encryption services with an in-memory key store.
    /// WARNING: Keys are lost when the application terminates!
    /// </summary>
    public static IServiceCollection AddPseudoPrf(this IServiceCollection services)
    {
        services.AddSingleton<IKeyStore, InMemoryKeyStore>();
        services.AddSingleton<ISymmetricEncryption, PseudoSymmetricEncryption>();
        services.AddSingleton<IAsymmetricEncryption, PseudoAsymmetricEncryption>();
        return services;
    }

    /// <summary>
    /// Adds PseudoPRF encryption services with a custom key store.
    /// </summary>
    /// <typeparam name="TKeyStore">The key store implementation type</typeparam>
    public static IServiceCollection AddPseudoPrf<TKeyStore>(this IServiceCollection services)
        where TKeyStore : class, IKeyStore
    {
        services.AddSingleton<IKeyStore, TKeyStore>();
        services.AddSingleton<ISymmetricEncryption, PseudoSymmetricEncryption>();
        services.AddSingleton<IAsymmetricEncryption, PseudoAsymmetricEncryption>();
        return services;
    }

    /// <summary>
    /// Adds PseudoPRF encryption services with a provided key store instance.
    /// </summary>
    public static IServiceCollection AddPseudoPrf(this IServiceCollection services, IKeyStore keyStore)
    {
        services.AddSingleton(keyStore);
        services.AddSingleton<ISymmetricEncryption, PseudoSymmetricEncryption>();
        services.AddSingleton<IAsymmetricEncryption, PseudoAsymmetricEncryption>();
        return services;
    }
}
