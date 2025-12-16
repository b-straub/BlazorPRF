namespace BlazorPRF.Sample.Services;

/// <summary>
/// Service for tracking database initialization status and errors.
/// Used to communicate schema migration issues to the UI.
/// </summary>
public interface IPrfDbInitializationService
{
    /// <summary>
    /// Gets or sets the error message if database initialization failed.
    /// </summary>
    string? ErrorMessage { get; set; }

    /// <summary>
    /// Whether the database was recreated due to schema changes.
    /// </summary>
    bool WasRecreated { get; set; }

    /// <summary>
    /// Clears any error state.
    /// </summary>
    void ClearError();
}

/// <summary>
/// Default implementation of database initialization service.
/// </summary>
public sealed class PrfDbInitializationService : IPrfDbInitializationService
{
    public string? ErrorMessage { get; set; }
    public bool WasRecreated { get; set; }

    public void ClearError()
    {
        ErrorMessage = null;
        WasRecreated = false;
    }
}
