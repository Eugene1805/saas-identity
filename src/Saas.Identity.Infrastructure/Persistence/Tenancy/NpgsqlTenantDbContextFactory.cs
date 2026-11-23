using Microsoft.EntityFrameworkCore;

namespace Saas.Identity.Infrastructure.Persistence.Tenancy;

internal sealed class NpgsqlTenantDbContextFactory(TenantDataSourcePool dataSourcePool)
    : ITenantDbContextFactory
{
    public TenantIdentityDbContext CreateDbContext(Guid tenantId)
    {
        var (_, dataSource) = dataSourcePool.GetConnection(tenantId);

        var optionsBuilder = new DbContextOptionsBuilder<TenantIdentityDbContext>();
        optionsBuilder.UseNpgsql(
            dataSource,
            npgsql => npgsql
                .MigrationsHistoryTable("__EFMigrationsHistory", "identity")
                .EnableRetryOnFailure());

        return new TenantIdentityDbContext(optionsBuilder.Options);
    }
}
