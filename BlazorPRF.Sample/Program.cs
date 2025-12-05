using Blazored.LocalStorage;
using BlazorPRF.Extensions;
using BlazorPRF.Sample;
using BlazorPRF.Sample.Services;
using BlazorPRF.UI;
using BlazorPRF.UI.Services;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.Components.Web;
using Microsoft.AspNetCore.Components.WebAssembly.Hosting;
using MudBlazor.Services;
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
builder.Services.AddBlazorPrf(builder.Configuration);

// Add BlazorPRF.UI observable models
ObservableModels.Initialize(builder.Services);

// Add PRF-based authentication state
builder.Services.AddAuthorizationCore();
builder.Services.AddSingleton<PrfAuthenticationStateProvider>();
builder.Services.AddSingleton<AuthenticationStateProvider>(sp => sp.GetRequiredService<PrfAuthenticationStateProvider>());

// Add TextCopy for clipboard support
builder.Services.InjectClipboard();

await builder.Build().RunAsync();
