using Microsoft.EntityFrameworkCore;
using Saas.Identity.Application.Ports;
using Saas.Identity.Domain.Entities;
using Saas.Identity.Domain.ValueObjects;

namespace Saas.Identity.Infrastructure.Persistence.Repositories;

internal sealed class EfAccountRepository(IdentityDbContext dbContext) : IAccountRepository
{
    public Task<IdentityAccount?> FindByClinicEmailAsync(
        Guid tenantId,
        string normalizedEmail,
        CancellationToken cancellationToken = default)
    {
        return dbContext.Accounts
            .FirstOrDefaultAsync(
                a => a.TenantId == tenantId && a.NormalizedEmail == normalizedEmail,
                cancellationToken);
    }

    public Task<IdentityAccount?> FindPlatformByEmailAsync(
        string normalizedEmail,
        CancellationToken cancellationToken = default)
    {
        return dbContext.Accounts
            .FirstOrDefaultAsync(
                a => a.TenantId == null && a.NormalizedEmail == normalizedEmail,
                cancellationToken);
    }

    public Task<IdentityAccount?> FindByIdAsync(
        Guid accountId,
        CancellationToken cancellationToken = default)
    {
        return dbContext.Accounts
            .FirstOrDefaultAsync(a => a.Id == accountId, cancellationToken);
    }

    public async Task<IReadOnlyList<IdentityAccount>> ListByTenantAsync(
        Guid tenantId,
        CancellationToken cancellationToken = default)
    {
        return await dbContext.Accounts
            .AsNoTracking()
            .Where(a => a.TenantId == tenantId)
            .OrderByDescending(a => a.CreatedAtUtc)
            .ToListAsync(cancellationToken);
    }

    public async Task<IReadOnlyDictionary<Guid, IReadOnlyList<RoleAuditEntry>>> ListRoleAuditByTenantAsync(
        Guid tenantId,
        CancellationToken cancellationToken = default)
    {
        var entries = await dbContext.RoleAuditEntries
            .AsNoTracking()
            .Where(r => r.TenantId == tenantId)
            .OrderByDescending(r => r.OccurredAtUtc)
            .ToListAsync(cancellationToken);

        return entries
            .GroupBy(r => r.AccountId)
            .ToDictionary(
                g => g.Key,
                g => (IReadOnlyList<RoleAuditEntry>)g.ToList());
    }

    public async Task<IReadOnlyList<RoleAuditEntry>> ListRoleAuditForAccountAsync(
        Guid accountId,
        CancellationToken cancellationToken = default)
    {
        return await dbContext.RoleAuditEntries
            .AsNoTracking()
            .Where(r => r.AccountId == accountId)
            .OrderByDescending(r => r.OccurredAtUtc)
            .ToListAsync(cancellationToken);
    }

    public Task<int> CountActiveByTenantAsync(
        Guid tenantId,
        CancellationToken cancellationToken = default)
    {
        return dbContext.Accounts
            .CountAsync(a => a.TenantId == tenantId && a.Active, cancellationToken);
    }

    public Task<int> CountActiveAdminsByTenantAsync(
        Guid tenantId,
        CancellationToken cancellationToken = default)
    {
        return dbContext.Accounts
            .CountAsync(
                a => a.TenantId == tenantId && a.Active && a.Role == OrgRole.ADMIN_CLINICA,
                cancellationToken);
    }

    public async Task AddAsync(
        IdentityAccount account,
        CancellationToken cancellationToken = default)
    {
        await dbContext.Accounts.AddAsync(account, cancellationToken);
        await dbContext.SaveChangesAsync(cancellationToken);
    }

    public async Task UpdateAsync(
        IdentityAccount account,
        CancellationToken cancellationToken = default)
    {
        if (dbContext.Entry(account).State == EntityState.Detached)
        {
            dbContext.Accounts.Update(account);
        }

        await dbContext.SaveChangesAsync(cancellationToken);
    }

    public async Task UpdateWithRoleAuditAsync(
        IdentityAccount account,
        RoleAuditEntry auditEntry,
        CancellationToken cancellationToken = default)
    {
        if (dbContext.Entry(account).State == EntityState.Detached)
        {
            dbContext.Accounts.Update(account);
        }

        await dbContext.RoleAuditEntries.AddAsync(auditEntry, cancellationToken);
        await dbContext.SaveChangesAsync(cancellationToken);
    }
}
