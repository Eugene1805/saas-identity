using Microsoft.EntityFrameworkCore;
using Saas.Identity.Domain.Entities;
using Saas.Identity.Infrastructure.Persistence.Configurations;

namespace Saas.Identity.Infrastructure.Persistence;

public sealed class TenantIdentityDbContext(DbContextOptions<TenantIdentityDbContext> options)
    : DbContext(options)
{
    public DbSet<IdentityAccount> Accounts => Set<IdentityAccount>();
    public DbSet<RefreshTokenSession> RefreshTokens => Set<RefreshTokenSession>();
    public DbSet<RoleAuditEntry> RoleAuditEntries => Set<RoleAuditEntry>();
    public DbSet<ProvisioningRecord> ProvisioningRecords => Set<ProvisioningRecord>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.HasDefaultSchema("identity");
        modelBuilder.ApplyConfiguration(new TenantIdentityAccountConfiguration());
        modelBuilder.ApplyConfiguration(new TenantRefreshTokenSessionConfiguration());
        modelBuilder.ApplyConfiguration(new RoleAuditEntryConfiguration());
        modelBuilder.ApplyConfiguration(new ProvisioningRecordConfiguration());
    }
}
