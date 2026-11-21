using Saas.Identity.Domain.Entities;

namespace Saas.Identity.Application.Ports;

public sealed record IssuedAccessToken(
    string Token,
    DateTimeOffset ExpiresAtUtc);

public interface ITokenIssuerPort
{
    int RefreshTokenLifetimeDays { get; }
    IssuedAccessToken IssueAccessToken(IdentityAccount account, DateTimeOffset utcNow);
    string GenerateRefreshToken();
    string HashRefreshToken(string rawRefreshToken);
}
