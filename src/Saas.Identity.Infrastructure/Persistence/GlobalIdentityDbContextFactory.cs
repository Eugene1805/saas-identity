using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;

namespace Saas.Identity.Infrastructure.Persistence;

public sealed class GlobalIdentityDbContextFactory : IDesignTimeDbContextFactory<GlobalIdentityDbContext>
{
    public GlobalIdentityDbContext CreateDbContext(string[] args)
    {
        var connectionString = Environment.GetEnvironmentVariable("ConnectionStrings__IdentityGlobalDb")
            ?? "Host=localhost;Port=5433;Database=vital_identity_global_designtime";

        var optionsBuilder = new DbContextOptionsBuilder<GlobalIdentityDbContext>();
        optionsBuilder.UseNpgsql(
            connectionString,
            npgsql => npgsql.MigrationsHistoryTable("__EFMigrationsHistory", "identity"));

        return new GlobalIdentityDbContext(optionsBuilder.Options);
    }
}
