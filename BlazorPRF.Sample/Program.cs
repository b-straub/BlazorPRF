using Blazored.LocalStorage;
using BlazorPRF.Crypto.Extensions;
using BlazorPRF.Persistence.Extensions;
using BlazorPRF.Persistence.Services;
using BlazorPRF.Sample;
using BlazorPRF.Sample.Services;
using BlazorPRF.UI.Services;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.Components.Web;
using Microsoft.AspNetCore.Components.WebAssembly.Hosting;
using MudBlazor.Services;
using SqliteWasmBlazor;
using TextCopy;

var builder = WebAssemblyHostBuilder.CreateDefault(args);
builder.RootComponents.Add<App>("#app");
builder.RootComponents.Add<HeadOutlet>("head::after");

// Add MudBlazor
builder.Services.AddMudServices();

// Add Blazored LocalStorage (still needed as fallback for new users)
builder.Services.AddBlazoredLocalStorageAsSingleton();

// Credential hint provider: checks DB first (authoritative), then LocalStorage (fallback)
builder.Services.AddSingleton<ICredentialHintProvider, CombinedCredentialHintProvider>();

// Add BlazorPRF with configuration
#pragma warning disable CA1416
builder.Services.AddBlazorPrf(builder.Configuration);
#pragma warning restore CA1416

// Add BlazorPRF.UI observable models
BlazorPRF.UI.ObservableModels.Initialize(builder.Services);

// Add BlazorPRF.Sample observable models (ContactsModel)
ObservableModels.Initialize(builder.Services);

// Add PRF-based authentication state
builder.Services.AddAuthorizationCore();
builder.Services.AddSingleton<PrfAuthenticationStateProvider>();
builder.Services.AddSingleton<AuthenticationStateProvider>(sp => sp.GetRequiredService<PrfAuthenticationStateProvider>());

// Add TextCopy for clipboard support
builder.Services.InjectClipboard();

// Add BlazorPRF.Persistence with SqliteWasm
builder.Services.AddBlazorPrfPersistence(options =>
{
#if DEBUG
    var connection = new SqliteWasmConnection("Data Source=BlazorPrf.db", Microsoft.Extensions.Logging.LogLevel.Information);
#else
    var connection = new SqliteWasmConnection("Data Source=BlazorPrf.db", LogLevel.Error);
#endif
    options.UseSqliteWasm(connection);
});

// Add invite persistence - interface from BlazorPRF.UI, implementation is app-specific
builder.Services.AddSingleton<IInvitePersistence, SqliteInvitePersistence>();
builder.Services.AddSingleton<InviteService>();

// Add database initialization service for error tracking
builder.Services.AddSingleton<IPrfDbInitializationService, PrfDbInitializationService>();

var host = builder.Build();

// Initialize SqliteWasm and validate/migrate database schema
await host.Services.InitializeSqliteWasmAsync();

var dbInitService = host.Services.GetRequiredService<IPrfDbInitializationService>();
var schemaService = host.Services.GetRequiredService<ISchemaVersionService>();

try
{
    var schemaResult = await schemaService.ValidateAndMigrateAsync();

    if (schemaResult == SchemaValidationResult.Recreated)
    {
        dbInitService.WasRecreated = true;
        Console.WriteLine("[Startup] Database was recreated due to schema changes.");
    }
}
catch (Exception ex)
{
    dbInitService.ErrorMessage = $"Database initialization failed: {ex.Message}";
    Console.WriteLine($"[Startup] Database error: {ex.Message}");
}

await host.RunAsync();
