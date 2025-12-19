using BlazorPRF.Persistence.Data;
using BlazorPRF.Persistence.Services;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace BlazorPRF.Persistence.Extensions;

/// <summary>
/// Extension methods for registering BlazorPRF.Persistence services.
/// </summary>
public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Adds BlazorPRF persistence services to the service collection.
    /// Includes DbContext factory and all persistence services.
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <param name="configureDbContext">Action to configure the DbContext options (e.g., UseSqliteWasm).</param>
    /// <returns>The service collection for chaining.</returns>
    public static IServiceCollection AddBlazorPrfPersistence(
        this IServiceCollection services,
        Action<DbContextOptionsBuilder> configureDbContext)
    {
        // DbContext factory - required for WASM (pooled contexts don't work in browser)
        services.AddDbContextFactory<PrfDbContext>(configureDbContext);

        // Services - Singleton for WASM (they use IDbContextFactory internally)
        services.AddSingleton<ITrustedContactService, TrustedContactService>();
        services.AddSingleton<IInvitationService, InvitationService>();
        services.AddSingleton<IUserProfileService, UserProfileService>();
        services.AddSingleton<IEncryptionCredentialService, EncryptionCredentialService>();
        services.AddSingleton<ISchemaVersionService, SchemaVersionService>();

        return services;
    }
}
