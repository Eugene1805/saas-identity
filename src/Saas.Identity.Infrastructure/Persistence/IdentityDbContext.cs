using Microsoft.EntityFrameworkCore;
using Saas.Identity.Domain.Entities;

namespace Saas.Identity.Infrastructure.Persistence;

public sealed class IdentityDbContext(DbContextOptions<IdentityDbContext> options)
    : DbContext(options)
{
    public DbSet<IdentityAccount> Accounts => Set<IdentityAccount>();
    public DbSet<RefreshTokenSession> RefreshTokens => Set<RefreshTokenSession>();
    public DbSet<RoleAuditEntry> RoleAuditEntries => Set<RoleAuditEntry>();
    public DbSet<ProvisioningRecord> ProvisioningRecords => Set<ProvisioningRecord>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.HasDefaultSchema("identity");
        modelBuilder.ApplyConfigurationsFromAssembly(typeof(IdentityDbContext).Assembly);
    }
}
