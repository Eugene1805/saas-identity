using Microsoft.EntityFrameworkCore;
using Saas.Identity.Application.Ports;
using Saas.Identity.Domain.Entities;

namespace Saas.Identity.Infrastructure.Persistence.Repositories;

internal sealed class EfRefreshTokenRepository(IdentityDbContext dbContext) : IRefreshTokenRepository
{
    public Task<RefreshTokenSession?> FindByTokenHashAsync(
        string tokenHash,
        CancellationToken cancellationToken = default)
    {
        return dbContext.RefreshTokens.FirstOrDefaultAsync(
            r => r.TokenHash == tokenHash,
            cancellationToken);
    }

    public async Task AddAsync(
        RefreshTokenSession session,
        CancellationToken cancellationToken = default)
    {
        await dbContext.RefreshTokens.AddAsync(session, cancellationToken);
        await dbContext.SaveChangesAsync(cancellationToken);
    }

    public async Task UpdateAsync(
        RefreshTokenSession session,
        CancellationToken cancellationToken = default)
    {
        dbContext.RefreshTokens.Update(session);
        await dbContext.SaveChangesAsync(cancellationToken);
    }

    public async Task RotateAsync(
        RefreshTokenSession previousSession,
        RefreshTokenSession newSession,
        CancellationToken cancellationToken = default)
    {
        if (dbContext.Entry(previousSession).State == EntityState.Detached)
        {
            dbContext.RefreshTokens.Update(previousSession);
        }

        await dbContext.RefreshTokens.AddAsync(newSession, cancellationToken);
        await dbContext.SaveChangesAsync(cancellationToken);
    }

    public async Task RevokeAllForAccountAsync(
        Guid accountId,
        DateTimeOffset revokedAtUtc,
        string reason,
        CancellationToken cancellationToken = default)
    {
        var activeSessions = await dbContext.RefreshTokens
            .Where(r => r.AccountId == accountId && r.RevokedAtUtc == null)
            .ToListAsync(cancellationToken);

        if (activeSessions.Count == 0)
        {
            return;
        }

        foreach (var session in activeSessions)
        {
            session.Revoke(revokedAtUtc, reason);
        }

        await dbContext.SaveChangesAsync(cancellationToken);
    }
}
