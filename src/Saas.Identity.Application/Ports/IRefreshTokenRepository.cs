using Saas.Identity.Domain.Entities;

namespace Saas.Identity.Application.Ports;

public interface IRefreshTokenRepository
{
    Task<RefreshTokenSession?> FindByTokenHashAsync(
        string tokenHash,
        CancellationToken cancellationToken = default);

    Task AddAsync(
        RefreshTokenSession session,
        CancellationToken cancellationToken = default);

    Task UpdateAsync(
        RefreshTokenSession session,
        CancellationToken cancellationToken = default);

    Task RotateAsync(
        RefreshTokenSession previousSession,
        RefreshTokenSession newSession,
        CancellationToken cancellationToken = default);

    Task RevokeAllForAccountAsync(
        Guid accountId,
        DateTimeOffset revokedAtUtc,
        string reason,
        CancellationToken cancellationToken = default);
}
