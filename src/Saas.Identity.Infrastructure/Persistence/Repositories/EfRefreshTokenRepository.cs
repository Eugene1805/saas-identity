using Microsoft.EntityFrameworkCore;
using Saas.Identity.Application.Ports;
using Saas.Identity.Domain.Entities;
using Saas.Identity.Domain.ValueObjects;
using Saas.Identity.Infrastructure.Persistence.Tenancy;

namespace Saas.Identity.Infrastructure.Persistence.Repositories;

internal sealed class EfRefreshTokenRepository(
    IDbContextFactory<GlobalIdentityDbContext> globalDbContextFactory,
    ITenantDbContextFactory tenantDbContextFactory) : IRefreshTokenRepository
{
    public async Task<RefreshTokenSession?> FindByTokenHashAsync(
        IdentityStoreScope scope,
        string tokenHash,
        CancellationToken cancellationToken = default)
    {
        if (scope.IsGlobal)
        {
            await using var globalDb = await globalDbContextFactory.CreateDbContextAsync(cancellationToken);
            return await globalDb.RefreshTokens
                .AsNoTracking()
                .FirstOrDefaultAsync(r => r.TenantId == null && r.TokenHash == tokenHash, cancellationToken);
        }

        var tenantId = scope.TenantId!.Value;
        return await TenantPersistenceHelper.ExecuteAsync(
            tenantDbContextFactory,
            tenantId,
            db => db.RefreshTokens
                .AsNoTracking()
                .FirstOrDefaultAsync(
                    r => r.TenantId == tenantId && r.TokenHash == tokenHash,
                    cancellationToken));
    }

    public async Task AddAsync(
        IdentityStoreScope scope,
        RefreshTokenSession session,
        CancellationToken cancellationToken = default)
    {
        EnsureScopeMatch(scope, session);

        if (scope.IsGlobal)
        {
            await using var globalDb = await globalDbContextFactory.CreateDbContextAsync(cancellationToken);
            await globalDb.RefreshTokens.AddAsync(session, cancellationToken);
            await globalDb.SaveChangesAsync(cancellationToken);
            return;
        }

        var tenantId = scope.TenantId!.Value;
        await TenantPersistenceHelper.ExecuteAsync(
            tenantDbContextFactory,
            tenantId,
            async db =>
            {
                await db.RefreshTokens.AddAsync(session, cancellationToken);
                await db.SaveChangesAsync(cancellationToken);
            });
    }

    public async Task UpdateAsync(
        IdentityStoreScope scope,
        RefreshTokenSession session,
        CancellationToken cancellationToken = default)
    {
        EnsureScopeMatch(scope, session);

        if (scope.IsGlobal)
        {
            await using var globalDb = await globalDbContextFactory.CreateDbContextAsync(cancellationToken);
            var tracked = await globalDb.RefreshTokens.FirstAsync(
                r => r.Id == session.Id && r.TenantId == null,
                cancellationToken);
            globalDb.Entry(tracked).CurrentValues.SetValues(session);
            await globalDb.SaveChangesAsync(cancellationToken);
            return;
        }

        var tenantId = scope.TenantId!.Value;
        await TenantPersistenceHelper.ExecuteAsync(
            tenantDbContextFactory,
            tenantId,
            async db =>
            {
                var tracked = await db.RefreshTokens.FirstAsync(
                    r => r.Id == session.Id && r.TenantId == tenantId,
                    cancellationToken);
                db.Entry(tracked).CurrentValues.SetValues(session);
                await db.SaveChangesAsync(cancellationToken);
            });
    }

    public async Task RotateAsync(
        IdentityStoreScope scope,
        RefreshTokenSession previousSession,
        RefreshTokenSession newSession,
        CancellationToken cancellationToken = default)
    {
        EnsureScopeMatch(scope, previousSession);
        EnsureScopeMatch(scope, newSession);

        if (scope.IsGlobal)
        {
            await using var globalDb = await globalDbContextFactory.CreateDbContextAsync(cancellationToken);
            var trackedPrevious = await globalDb.RefreshTokens.FirstAsync(
                r => r.Id == previousSession.Id && r.TenantId == null,
                cancellationToken);
            globalDb.Entry(trackedPrevious).CurrentValues.SetValues(previousSession);
            await globalDb.RefreshTokens.AddAsync(newSession, cancellationToken);
            await globalDb.SaveChangesAsync(cancellationToken);
            return;
        }

        var tenantId = scope.TenantId!.Value;
        await TenantPersistenceHelper.ExecuteAsync(
            tenantDbContextFactory,
            tenantId,
            async db =>
            {
                var trackedPrevious = await db.RefreshTokens.FirstAsync(
                    r => r.Id == previousSession.Id && r.TenantId == tenantId,
                    cancellationToken);
                db.Entry(trackedPrevious).CurrentValues.SetValues(previousSession);
                await db.RefreshTokens.AddAsync(newSession, cancellationToken);
                await db.SaveChangesAsync(cancellationToken);
            });
    }

    public async Task RevokeAllForAccountAsync(
        IdentityStoreScope scope,
        Guid accountId,
        DateTimeOffset revokedAtUtc,
        string reason,
        CancellationToken cancellationToken = default)
    {
        if (scope.IsGlobal)
        {
            await using var globalDb = await globalDbContextFactory.CreateDbContextAsync(cancellationToken);
            var sessions = await globalDb.RefreshTokens
                .Where(r => r.TenantId == null && r.AccountId == accountId && r.RevokedAtUtc == null)
                .ToListAsync(cancellationToken);
            if (sessions.Count == 0)
            {
                return;
            }

            foreach (var session in sessions)
            {
                session.Revoke(revokedAtUtc, reason);
            }

            await globalDb.SaveChangesAsync(cancellationToken);
            return;
        }

        var tenantId = scope.TenantId!.Value;
        await TenantPersistenceHelper.ExecuteAsync(
            tenantDbContextFactory,
            tenantId,
            async db =>
            {
                var sessions = await db.RefreshTokens
                    .Where(r => r.TenantId == tenantId && r.AccountId == accountId && r.RevokedAtUtc == null)
                    .ToListAsync(cancellationToken);
                if (sessions.Count == 0)
                {
                    return;
                }

                foreach (var session in sessions)
                {
                    session.Revoke(revokedAtUtc, reason);
                }

                await db.SaveChangesAsync(cancellationToken);
            });
    }

    private static void EnsureScopeMatch(IdentityStoreScope scope, RefreshTokenSession session)
    {
        if (session.TenantId != scope.TenantId)
        {
            throw new InvalidOperationException("El ámbito del refresh token no coincide con la base de datos seleccionada.");
        }
    }
}
