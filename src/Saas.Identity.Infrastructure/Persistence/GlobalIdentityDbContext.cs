using Microsoft.EntityFrameworkCore;
using Saas.Identity.Domain.Entities;
using Saas.Identity.Infrastructure.Persistence.Configurations;

namespace Saas.Identity.Infrastructure.Persistence;

public sealed class GlobalIdentityDbContext(DbContextOptions<GlobalIdentityDbContext> options)
    : DbContext(options)
{
    public DbSet<IdentityAccount> Accounts => Set<IdentityAccount>();
    public DbSet<RefreshTokenSession> RefreshTokens => Set<RefreshTokenSession>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.HasDefaultSchema("identity");
        modelBuilder.ApplyConfiguration(new GlobalIdentityAccountConfiguration());
        modelBuilder.ApplyConfiguration(new GlobalRefreshTokenSessionConfiguration());
    }
}
