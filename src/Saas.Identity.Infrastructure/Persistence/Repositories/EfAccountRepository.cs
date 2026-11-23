using Microsoft.EntityFrameworkCore;
using Saas.Identity.Application.Ports;
using Saas.Identity.Domain.Entities;
using Saas.Identity.Domain.ValueObjects;
using Saas.Identity.Infrastructure.Persistence.Tenancy;

namespace Saas.Identity.Infrastructure.Persistence.Repositories;

internal sealed class EfAccountRepository(
    IDbContextFactory<GlobalIdentityDbContext> globalDbContextFactory,
    ITenantDbContextFactory tenantDbContextFactory) : IAccountRepository
{
    public Task<IdentityAccount?> FindByClinicEmailAsync(
        Guid tenantId,
        string normalizedEmail,
        CancellationToken cancellationToken = default)
    {
        return TenantPersistenceHelper.ExecuteAsync(
            tenantDbContextFactory,
            tenantId,
            db => db.Accounts
                .AsNoTracking()
                .FirstOrDefaultAsync(
                    a => a.TenantId == tenantId && a.NormalizedEmail == normalizedEmail,
                    cancellationToken));
    }

    public async Task<IdentityAccount?> FindPlatformByEmailAsync(
        string normalizedEmail,
        CancellationToken cancellationToken = default)
    {
        await using var dbContext = await globalDbContextFactory.CreateDbContextAsync(cancellationToken);
        return await dbContext.Accounts
            .AsNoTracking()
            .FirstOrDefaultAsync(
                a => a.TenantId == null && a.NormalizedEmail == normalizedEmail,
                cancellationToken);
    }

    public async Task<IdentityAccount?> FindByIdAsync(
        IdentityStoreScope scope,
        Guid accountId,
        CancellationToken cancellationToken = default)
    {
        if (scope.IsGlobal)
        {
            await using var globalDb = await globalDbContextFactory.CreateDbContextAsync(cancellationToken);
            return await globalDb.Accounts
                .AsNoTracking()
                .FirstOrDefaultAsync(a => a.TenantId == null && a.Id == accountId, cancellationToken);
        }

        var tenantId = scope.TenantId!.Value;
        return await TenantPersistenceHelper.ExecuteAsync(
            tenantDbContextFactory,
            tenantId,
            db => db.Accounts
                .AsNoTracking()
                .FirstOrDefaultAsync(
                    a => a.TenantId == tenantId && a.Id == accountId,
                    cancellationToken));
    }

    public Task<IReadOnlyList<IdentityAccount>> ListByTenantAsync(
        Guid tenantId,
        CancellationToken cancellationToken = default)
    {
        return TenantPersistenceHelper.ExecuteAsync<IReadOnlyList<IdentityAccount>>(
            tenantDbContextFactory,
            tenantId,
            async db => await db.Accounts
                .AsNoTracking()
                .Where(a => a.TenantId == tenantId)
                .OrderByDescending(a => a.CreatedAtUtc)
                .ToListAsync(cancellationToken));
    }

    public Task<IReadOnlyDictionary<Guid, IReadOnlyList<RoleAuditEntry>>> ListRoleAuditByTenantAsync(
        Guid tenantId,
        CancellationToken cancellationToken = default)
    {
        return TenantPersistenceHelper.ExecuteAsync<IReadOnlyDictionary<Guid, IReadOnlyList<RoleAuditEntry>>>(
            tenantDbContextFactory,
            tenantId,
            async db =>
            {
                var entries = await db.RoleAuditEntries
                    .AsNoTracking()
                    .Where(r => r.TenantId == tenantId)
                    .OrderByDescending(r => r.OccurredAtUtc)
                    .ToListAsync(cancellationToken);

                return entries
                    .GroupBy(r => r.AccountId)
                    .ToDictionary(
                        g => g.Key,
                        g => (IReadOnlyList<RoleAuditEntry>)g.ToList());
            });
    }

    public Task<IReadOnlyList<RoleAuditEntry>> ListRoleAuditForAccountAsync(
        Guid tenantId,
        Guid accountId,
        CancellationToken cancellationToken = default)
    {
        return TenantPersistenceHelper.ExecuteAsync<IReadOnlyList<RoleAuditEntry>>(
            tenantDbContextFactory,
            tenantId,
            async db => await db.RoleAuditEntries
                .AsNoTracking()
                .Where(r => r.TenantId == tenantId && r.AccountId == accountId)
                .OrderByDescending(r => r.OccurredAtUtc)
                .ToListAsync(cancellationToken));
    }

    public Task<int> CountActiveByTenantAsync(
        Guid tenantId,
        CancellationToken cancellationToken = default)
    {
        return TenantPersistenceHelper.ExecuteAsync(
            tenantDbContextFactory,
            tenantId,
            db => db.Accounts.CountAsync(a => a.TenantId == tenantId && a.Active, cancellationToken));
    }

    public Task<int> CountActiveAdminsByTenantAsync(
        Guid tenantId,
        CancellationToken cancellationToken = default)
    {
        return TenantPersistenceHelper.ExecuteAsync(
            tenantDbContextFactory,
            tenantId,
            db => db.Accounts.CountAsync(
                a => a.TenantId == tenantId && a.Active && a.Role == OrgRole.ADMIN_CLINICA,
                cancellationToken));
    }

    public async Task AddAsync(
        IdentityStoreScope scope,
        IdentityAccount account,
        CancellationToken cancellationToken = default)
    {
        EnsureScopeMatch(scope, account);

        if (scope.IsGlobal)
        {
            await using var globalDb = await globalDbContextFactory.CreateDbContextAsync(cancellationToken);
            await globalDb.Accounts.AddAsync(account, cancellationToken);
            await globalDb.SaveChangesAsync(cancellationToken);
            return;
        }

        var tenantId = scope.TenantId!.Value;
        await TenantPersistenceHelper.ExecuteAsync(
            tenantDbContextFactory,
            tenantId,
            async db =>
            {
                await db.Accounts.AddAsync(account, cancellationToken);
                await db.SaveChangesAsync(cancellationToken);
            });
    }

    public async Task UpdateAsync(
        IdentityStoreScope scope,
        IdentityAccount account,
        CancellationToken cancellationToken = default)
    {
        EnsureScopeMatch(scope, account);

        if (scope.IsGlobal)
        {
            await using var globalDb = await globalDbContextFactory.CreateDbContextAsync(cancellationToken);
            var tracked = await globalDb.Accounts.FirstAsync(
                a => a.Id == account.Id && a.TenantId == null,
                cancellationToken);
            TenantPersistenceHelper.SyncAccountState(globalDb, tracked, account);
            await globalDb.SaveChangesAsync(cancellationToken);
            return;
        }

        var tenantId = scope.TenantId!.Value;
        await TenantPersistenceHelper.ExecuteAsync(
            tenantDbContextFactory,
            tenantId,
            async db =>
            {
                var tracked = await db.Accounts.FirstAsync(
                    a => a.Id == account.Id && a.TenantId == tenantId,
                    cancellationToken);
                TenantPersistenceHelper.SyncAccountState(db, tracked, account);
                await db.SaveChangesAsync(cancellationToken);
            });
    }

    public Task UpdateWithRoleAuditAsync(
        Guid tenantId,
        IdentityAccount account,
        RoleAuditEntry auditEntry,
        CancellationToken cancellationToken = default)
    {
        var scope = IdentityStoreScope.ForTenant(tenantId);
        EnsureScopeMatch(scope, account);
        if (auditEntry.TenantId != tenantId)
        {
            throw new InvalidOperationException("La entrada de auditoría no coincide con el tenant de destino.");
        }

        return TenantPersistenceHelper.ExecuteAsync(
            tenantDbContextFactory,
            tenantId,
            async db =>
            {
                var tracked = await db.Accounts.FirstAsync(
                    a => a.Id == account.Id && a.TenantId == tenantId,
                    cancellationToken);
                TenantPersistenceHelper.SyncAccountState(db, tracked, account);
                await db.RoleAuditEntries.AddAsync(auditEntry, cancellationToken);
                await db.SaveChangesAsync(cancellationToken);
            });
    }

    private static void EnsureScopeMatch(IdentityStoreScope scope, IdentityAccount account)
    {
        if (account.TenantId != scope.TenantId)
        {
            throw new InvalidOperationException("El ámbito de base de datos no coincide con el TenantId de la cuenta.");
        }
    }
}
