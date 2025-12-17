using BlazorPRF.Persistence.Data;
using Microsoft.AspNetCore.Components;
using Microsoft.EntityFrameworkCore;
using RxBlazorV2.Interface;
using RxBlazorV2.Model;
using SqliteWasmBlazor;
using System.Diagnostics.CodeAnalysis;

namespace BlazorPRF.Sample.Models;

/// <summary>
/// Reactive model for database initialization status and error handling.
/// Replaces IPrfDbInitializationService with reactive patterns.
/// Note: No [ObservableComponent] - this is a UI-less model accessed via injection.
/// </summary>
[ObservableModelScope(ModelScope.Singleton)]
public partial class DbInitModel : ObservableModel
{
    [SuppressMessage("RxBlazorGenerator", "RXBG050:Partial constructor parameter type may not be registered in DI", Justification = "Services registered externally")]
    public partial DbInitModel(IDbContextFactory<PrfDbContext> dbContextFactory, NavigationManager navigationManager);

    /// <summary>
    /// Error message if database initialization failed.
    /// </summary>
    public partial string? ErrorMessage { get; set; }

    /// <summary>
    /// Whether the database was recreated due to schema changes.
    /// </summary>
    public partial bool WasRecreated { get; set; }

    /// <summary>
    /// Whether there's a schema mismatch (Release mode).
    /// </summary>
    public partial bool HasSchemaMismatch { get; set; }

    /// <summary>
    /// Whether database initialization failed.
    /// </summary>
    public partial bool HasInitError { get; set; }

    /// <summary>
    /// Whether a reset operation is in progress.
    /// </summary>
    public partial bool IsResetting { get; set; }

    // Commands

    [ObservableCommand(nameof(ResetDatabaseAsync), nameof(CanReset))]
    public partial IObservableCommandAsync ResetDatabase { get; }

    [ObservableCommand(nameof(ClearErrorImpl))]
    public partial IObservableCommand ClearError { get; }

    [ObservableCommand(nameof(DismissRecreatedImpl))]
    public partial IObservableCommand DismissRecreated { get; }

    private bool CanReset() => !IsResetting;

    private async Task ResetDatabaseAsync(CancellationToken ct)
    {
        IsResetting = true;

        try
        {
            // Delete the database file from OPFS SAHPool
            await SqliteWasmWorkerBridge.Instance.DeleteDatabaseAsync("BlazorPrf.db");

            // Recreate database schema
            await using var context = await DbContextFactory.CreateDbContextAsync(ct);
            await context.Database.EnsureCreatedAsync(ct);

            // Clear error and reload - forceLoad ensures clean app restart
            ClearErrorImpl();
            NavigationManager.NavigateTo("./", forceLoad: true);
        }
        catch (Exception ex)
        {
            ErrorMessage += $"\n\nReset failed: {ex.Message}";
            IsResetting = false;
        }
    }

    private void ClearErrorImpl()
    {
        ErrorMessage = null;
        WasRecreated = false;
    }

    private void DismissRecreatedImpl()
    {
        WasRecreated = false;
    }
}
