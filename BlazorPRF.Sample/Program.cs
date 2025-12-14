using Blazored.LocalStorage;
using BlazorPRF.Noble.Crypto.Extensions;
using BlazorPRF.Persistence.Data;
using BlazorPRF.Persistence.Extensions;
using BlazorPRF.Sample;
using BlazorPRF.Sample.Services;
using BlazorPRF.UI.Services;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.Components.Web;
using Microsoft.AspNetCore.Components.WebAssembly.Hosting;
using Microsoft.EntityFrameworkCore;
using MudBlazor.Services;
using SqliteWasmBlazor;
using TextCopy;

var builder = WebAssemblyHostBuilder.CreateDefault(args);
builder.RootComponents.Add<App>("#app");
builder.RootComponents.Add<HeadOutlet>("head::after");

// Add MudBlazor
builder.Services.AddMudServices();

// Add Blazored LocalStorage for credential hint persistence (as singleton for WASM)
builder.Services.AddBlazoredLocalStorageAsSingleton();
builder.Services.AddSingleton<ICredentialHintProvider, LocalStorageCredentialHintProvider>();

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

var host = builder.Build();

// Initialize SqliteWasm and ensure database is created
await host.Services.InitializeSqliteWasmAsync();
await using (var scope = host.Services.CreateAsyncScope())
{
    var factory = scope.ServiceProvider.GetRequiredService<IDbContextFactory<PrfDbContext>>();
    await using var db = await factory.CreateDbContextAsync();
    await db.Database.EnsureCreatedAsync();
}

await host.RunAsync();
