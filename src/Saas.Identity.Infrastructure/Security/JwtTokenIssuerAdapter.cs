using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Saas.Identity.Application.Ports;
using Saas.Identity.Domain.Entities;

namespace Saas.Identity.Infrastructure.Security;

public sealed class JwtTokenIssuerAdapter(IOptions<JwtOptions> optionsAccessor) : ITokenIssuerPort
{
    private readonly JwtOptions _options = optionsAccessor.Value;

    public int RefreshTokenLifetimeDays => Math.Max(1, _options.RefreshTokenDays);

    public IssuedAccessToken IssueAccessToken(IdentityAccount account, DateTimeOffset utcNow)
    {
        if (string.IsNullOrWhiteSpace(_options.SigningKey) ||
            Encoding.UTF8.GetByteCount(_options.SigningKey) < 32)
        {
            throw new InvalidOperationException("Jwt:SigningKey debe tener al menos 32 bytes.");
        }

        var expiresAtUtc = utcNow.AddMinutes(Math.Max(1, _options.AccessTokenMinutes));
        var claims = new List<Claim>
        {
            new(JwtRegisteredClaimNames.Sub, account.Id.ToString()),
            new(JwtRegisteredClaimNames.Email, account.Email),
            new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            new(JwtRegisteredClaimNames.Iat, utcNow.ToUnixTimeSeconds().ToString(), ClaimValueTypes.Integer64),
            new("role", account.Role.ToString()),
            new("full_name", account.FullName),
        };

        if (account.TenantId is Guid tenantId)
        {
            claims.Add(new Claim("tenant_id", tenantId.ToString()));
        }

        var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_options.SigningKey));
        var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

        var descriptor = new JwtSecurityToken(
            issuer: _options.Issuer,
            audience: _options.Audience,
            claims: claims,
            notBefore: utcNow.UtcDateTime,
            expires: expiresAtUtc.UtcDateTime,
            signingCredentials: credentials);

        var encodedToken = new JwtSecurityTokenHandler().WriteToken(descriptor);
        return new IssuedAccessToken(encodedToken, expiresAtUtc);
    }

    public string GenerateRefreshToken()
    {
        var bytes = RandomNumberGenerator.GetBytes(32);
        return Convert.ToBase64String(bytes)
            .Replace('+', '-')
            .Replace('/', '_')
            .TrimEnd('=');
    }

    public string HashRefreshToken(string rawRefreshToken)
    {
        var hashBytes = SHA256.HashData(Encoding.UTF8.GetBytes(rawRefreshToken));
        return Convert.ToHexStringLower(hashBytes);
    }
}
