using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;

namespace Saas.Identity.Infrastructure.Persistence;

public sealed class TenantIdentityDbContextFactory : IDesignTimeDbContextFactory<TenantIdentityDbContext>
{
    public TenantIdentityDbContext CreateDbContext(string[] args)
    {
        var connectionString = Environment.GetEnvironmentVariable("ConnectionStrings__IdentityTenantDesignTimeDb")
            ?? "Host=localhost;Port=5436;Database=vital_identity_tenant_designtime";

        var optionsBuilder = new DbContextOptionsBuilder<TenantIdentityDbContext>();
        optionsBuilder.UseNpgsql(
            connectionString,
            npgsql => npgsql.MigrationsHistoryTable("__EFMigrationsHistory", "identity"));

        return new TenantIdentityDbContext(optionsBuilder.Options);
    }
}
