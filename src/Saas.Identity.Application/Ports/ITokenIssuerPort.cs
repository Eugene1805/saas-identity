using Saas.Identity.Domain.Entities;
using Saas.Identity.Domain.ValueObjects;

namespace Saas.Identity.Application.Ports;

public sealed record IssuedAccessToken(
    string Token,
    DateTimeOffset ExpiresAtUtc);

public interface ITokenIssuerPort
{
    int RefreshTokenLifetimeDays { get; }
    IssuedAccessToken IssueAccessToken(IdentityAccount account, DateTimeOffset utcNow);
    string GenerateRefreshToken(Guid? tenantId);
    bool TryResolveRefreshTokenScope(string rawRefreshToken, out IdentityStoreScope scope);
    string HashRefreshToken(string rawRefreshToken);
}
