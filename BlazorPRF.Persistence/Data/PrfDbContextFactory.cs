using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;

namespace BlazorPRF.Persistence.Data;

/// <summary>
/// Design-time factory for EF Core tools (migrations, etc.).
/// Uses standard SQLite for design-time operations (not SqliteWasm).
/// Runtime uses SqliteWasm with OPFS persistence.
/// </summary>
public sealed class PrfDbContextFactory : IDesignTimeDbContextFactory<PrfDbContext>
{
    public PrfDbContext CreateDbContext(string[] args)
    {
        var optionsBuilder = new DbContextOptionsBuilder<PrfDbContext>();

        // Use standard SQLite for design-time (no browser, no worker)
        optionsBuilder.UseSqlite("Data Source=:memory:");

        return new PrfDbContext(optionsBuilder.Options);
    }
}
