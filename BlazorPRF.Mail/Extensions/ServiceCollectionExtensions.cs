using BlazorPRF.Api.Extensions;
using BlazorPRF.Mail.Services;
using Microsoft.Extensions.DependencyInjection;

namespace BlazorPRF.Mail.Extensions;

/// <summary>
/// Extension methods for registering mail services.
/// </summary>
public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Adds the mail services.
    /// Also adds the API client services as a dependency.
    /// MailApiModel is registered via RxBlazorV2 generator - call BlazorPRF.Mail.ObservableModels.Initialize(services) in Program.cs.
    /// </summary>
    /// <param name="services">Service collection</param>
    /// <returns>Service collection for chaining</returns>
    public static IServiceCollection AddMailServices(this IServiceCollection services)
    {
        services.AddPrfApiClient();
        services.AddSingleton<IMailService, MailService>();
        services.AddSingleton<IProfileSyncService, ProfileSyncService>();
        services.AddSingleton<IRelayRegistrationService, RelayRegistrationService>();
        return services;
    }
}
