namespace Saas.Identity.Infrastructure.Persistence.Tenancy;

public interface ITenantDbContextFactory
{
    TenantIdentityDbContext CreateDbContext(Guid tenantId);
}
