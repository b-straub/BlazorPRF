using Blazored.LocalStorage;
using BlazorPRF.Crypto.Extensions;
using BlazorPRF.Persistence.Extensions;
using BlazorPRF.Persistence.Services;
using BlazorPRF.Sample;
using BlazorPRF.Sample.Services;
using BlazorPRF.UI.Models;
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
    var connection = new SqliteWasmConnection("Data Source=BlazorPrf.db", LogLevel.Information);
#else
    var connection = new SqliteWasmConnection("Data Source=BlazorPrf.db", LogLevel.Error);
#endif
    options.UseSqliteWasm(connection);
});

// Add invite persistence - interface from BlazorPRF.UI, implementation is app-specific
builder.Services.AddSingleton<IInvitePersistence, SqliteInvitePersistence>();

// Add contacts service for managing trusted contacts
builder.Services.AddSingleton<IContactsService, ContactsService>();

// DbInitModel is registered via RxBlazorV2 generator (Singleton scope)

var host = builder.Build();

// Initialize SqliteWasm and validate/migrate database schema
await host.Services.InitializeSqliteWasmAsync();

var dbInitModel = host.Services.GetRequiredService<DbInitModel>();
var schemaService = host.Services.GetRequiredService<ISchemaVersionService>();

try
{
    var schemaResult = await schemaService.ValidateAndMigrateAsync();
    
    switch (schemaResult)
    {
        case SchemaValidationResult.RECREATED:
            dbInitModel.WasRecreated = true;
            dbInitModel.ErrorMessage = "Database schema has changed!";
            break;
        case SchemaValidationResult.MISMATCH:
            dbInitModel.HasSchemaMismatch = true;
            dbInitModel.ErrorMessage = "Database schema mismatch. Please clear browser data to reset.";
            break;
    }
}
catch (Exception ex)
{
    dbInitModel.HasInitError = true;
    dbInitModel.ErrorMessage = $"Database initialization failed: {ex.Message}";
    Console.WriteLine($"[Startup] Database error: {ex.Message}");
}

await host.RunAsync();
