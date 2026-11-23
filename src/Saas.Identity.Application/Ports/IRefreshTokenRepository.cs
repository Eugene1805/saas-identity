using Saas.Identity.Domain.Entities;
using Saas.Identity.Domain.ValueObjects;

namespace Saas.Identity.Application.Ports;

public interface IRefreshTokenRepository
{
    Task<RefreshTokenSession?> FindByTokenHashAsync(
        IdentityStoreScope scope,
        string tokenHash,
        CancellationToken cancellationToken = default);

    Task AddAsync(
        IdentityStoreScope scope,
        RefreshTokenSession session,
        CancellationToken cancellationToken = default);

    Task UpdateAsync(
        IdentityStoreScope scope,
        RefreshTokenSession session,
        CancellationToken cancellationToken = default);

    Task RotateAsync(
        IdentityStoreScope scope,
        RefreshTokenSession previousSession,
        RefreshTokenSession newSession,
        CancellationToken cancellationToken = default);

    Task RevokeAllForAccountAsync(
        IdentityStoreScope scope,
        Guid accountId,
        DateTimeOffset revokedAtUtc,
        string reason,
        CancellationToken cancellationToken = default);
}
