using BlazorPRF.Crypto.Extensions;
using BlazorPRF.Sample;
using BlazorPRF.Sample.Services;
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

// Credential hint provider: simple in-memory for core sample
builder.Services.AddSingleton<ICredentialHintProvider, InMemoryCredentialHintProvider>();

// Add BlazorPRF with configuration
#pragma warning disable CA1416
builder.Services.AddBlazorPrf(builder.Configuration);
#pragma warning restore CA1416

// Add BlazorPRF.UI observable models (PrfModel)
BlazorPRF.UI.ObservableModels.Initialize(builder.Services);

// RxBlazorV2.MudBlazor
RxBlazorV2.MudBlazor.ObservableModels.Initialize(builder.Services);

// Add PRF-based authentication state
builder.Services.AddAuthorizationCore();
builder.Services.AddSingleton<PrfAuthenticationStateProvider>();
builder.Services.AddSingleton<AuthenticationStateProvider>(sp => sp.GetRequiredService<PrfAuthenticationStateProvider>());

// Add TextCopy for clipboard support
builder.Services.InjectClipboard();

var host = builder.Build();
await host.RunAsync();
