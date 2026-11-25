using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Saas.Identity.Application.Ports;
using Saas.Identity.Domain.Entities;
using Saas.Identity.Domain.ValueObjects;

namespace Saas.Identity.Infrastructure.Security;

public sealed class JwtTokenIssuerAdapter(JwtCryptoMaterial cryptoMaterial) : ITokenIssuerPort
{
    private readonly JwtCryptoMaterial _cryptoMaterial = cryptoMaterial;

    public JwtTokenIssuerAdapter(IOptions<JwtOptions> optionsAccessor)
        : this(JwtCryptoMaterial.Create(optionsAccessor.Value))
    {
    }

    public int RefreshTokenLifetimeDays => _cryptoMaterial.RefreshTokenDays;

    public IssuedAccessToken IssueAccessToken(IdentityAccount account, DateTimeOffset utcNow)
    {
        var expiresAtUtc = utcNow.AddMinutes(_cryptoMaterial.AccessTokenMinutes);
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

        var descriptor = new JwtSecurityToken(
            issuer: _cryptoMaterial.Issuer,
            audience: _cryptoMaterial.Audience,
            claims: claims,
            notBefore: utcNow.UtcDateTime,
            expires: expiresAtUtc.UtcDateTime,
            signingCredentials: _cryptoMaterial.SigningCredentials);

        var encodedToken = new JwtSecurityTokenHandler().WriteToken(descriptor);
        return new IssuedAccessToken(encodedToken, expiresAtUtc);
    }

    public string GenerateRefreshToken(Guid? tenantId)
    {
        if (tenantId == Guid.Empty)
        {
            throw new ArgumentException("El tenantId del refresh token no puede ser Guid.Empty.", nameof(tenantId));
        }

        var randomPart = ToBase64Url(RandomNumberGenerator.GetBytes(32));
        var scopePayload = tenantId is Guid tid
            ? $"t.{tid:N}.{randomPart}"
            : $"g.{randomPart}";

        var tagBytes = ComputeRoutingMacTag(_cryptoMaterial.RefreshTokenRoutingMacKey, scopePayload);
        return $"rt.{scopePayload}.{ToBase64Url(tagBytes)}";
    }

    public bool TryResolveRefreshTokenScope(string rawRefreshToken, out IdentityStoreScope scope)
    {
        scope = default;
        if (string.IsNullOrWhiteSpace(rawRefreshToken))
        {
            return false;
        }

        var trimmed = rawRefreshToken.Trim();
        var segments = trimmed.Split('.', StringSplitOptions.None);
        var macKey = _cryptoMaterial.RefreshTokenRoutingMacKey;

        if (segments.Length == 4 &&
            segments[0] == "rt" &&
            segments[1] == "g")
        {
            if (!TryFromBase64Url(segments[2], out var randomBytes) || randomBytes.Length != 32 ||
                !TryFromBase64Url(segments[3], out var providedTag) || providedTag.Length != 16)
            {
                return false;
            }

            var expectedTag = ComputeRoutingMacTag(macKey, $"g.{segments[2]}");
            if (!CryptographicOperations.FixedTimeEquals(expectedTag, providedTag))
            {
                return false;
            }

            scope = IdentityStoreScope.Global;
            return true;
        }

        if (segments.Length == 5 &&
            segments[0] == "rt" &&
            segments[1] == "t")
        {
            if (segments[2].Length != 32 ||
                !Guid.TryParseExact(segments[2], "N", out var tenantId) ||
                tenantId == Guid.Empty ||
                !TryFromBase64Url(segments[3], out var randomBytes) || randomBytes.Length != 32 ||
                !TryFromBase64Url(segments[4], out var providedTag) || providedTag.Length != 16)
            {
                return false;
            }

            var expectedTag = ComputeRoutingMacTag(macKey, $"t.{tenantId:N}.{segments[3]}");
            if (!CryptographicOperations.FixedTimeEquals(expectedTag, providedTag))
            {
                return false;
            }

            scope = IdentityStoreScope.ForTenant(tenantId);
            return true;
        }

        return false;
    }

    public string HashRefreshToken(string rawRefreshToken)
    {
        var hashBytes = SHA256.HashData(Encoding.UTF8.GetBytes(rawRefreshToken));
        return Convert.ToHexStringLower(hashBytes);
    }

    private static byte[] ComputeRoutingMacTag(ReadOnlySpan<byte> macKey, string payload)
    {
        Span<byte> fullMac = stackalloc byte[HMACSHA256.HashSizeInBytes];
        HMACSHA256.HashData(macKey, Encoding.UTF8.GetBytes(payload), fullMac);
        return fullMac[..16].ToArray();
    }

    private static string ToBase64Url(byte[] bytes) =>
        Convert.ToBase64String(bytes)
            .Replace('+', '-')
            .Replace('/', '_')
            .TrimEnd('=');

    private static bool TryFromBase64Url(string input, out byte[] bytes)
    {
        bytes = [];
        if (string.IsNullOrEmpty(input))
        {
            return false;
        }

        var padded = input.Replace('-', '+').Replace('_', '/');
        switch (padded.Length % 4)
        {
            case 2:
                padded += "==";
                break;
            case 3:
                padded += "=";
                break;
            case 1:
                return false;
        }

        try
        {
            bytes = Convert.FromBase64String(padded);
            return true;
        }
        catch (FormatException)
        {
            return false;
        }
    }
}
