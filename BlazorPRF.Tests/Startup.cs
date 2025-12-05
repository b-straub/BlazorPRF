using BlazorPRF.Configuration;
using BlazorPRF.Services;
using Microsoft.Extensions.DependencyInjection;

namespace BlazorPRF.Tests;

public class Startup
{
    public void ConfigureServices(IServiceCollection services)
    {
        // Configure default options
        services.Configure<PrfOptions>(_ => { });
        services.Configure<KeyCacheOptions>(_ => { });

        // Register services
        services.AddScoped<ISecureKeyCache, SecureKeyCache>();
    }
}
