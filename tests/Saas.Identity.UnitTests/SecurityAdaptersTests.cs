using System.IdentityModel.Tokens.Jwt;
using Saas.Identity.Domain.Entities;
using Saas.Identity.Domain.ValueObjects;
using Saas.Identity.Infrastructure.Security;

namespace Saas.Identity.UnitTests;

public sealed class SecurityAdaptersTests
{
    [Fact]
    public void Pbkdf2PasswordHasher_HashesWithRandomSaltAndVerifies()
    {
        var hasher = new Pbkdf2PasswordHasherAdapter();

        var hash1 = hasher.Hash("Vital2026!");
        var hash2 = hasher.Hash("Vital2026!");

        Assert.NotEqual(hash1, hash2);
        Assert.StartsWith("pbkdf2-sha256$", hash1);
        Assert.True(hasher.Verify(hash1, "Vital2026!"));
        Assert.False(hasher.Verify(hash1, "WrongPassword!"));
        Assert.False(hasher.Verify("malformed-hash", "Vital2026!"));
    }

    [Fact]
    public void JwtTokenIssuer_IncludesTenantRoleSubClaimsAndDeterministicSha256Hash()
    {
        var issuer = new JwtTokenIssuerAdapter(Microsoft.Extensions.Options.Options.Create(new JwtOptions
        {
            Issuer = "saas-identity",
            Audience = "vital-saas",
            SigningKey = "UnitTestSigningKeyMustBeAtLeast32Bytes!",
            AccessTokenMinutes = 20,
            RefreshTokenDays = 7,
        }));

        var accountId = Guid.Parse("20000000-0000-0000-0000-000000000002");
        var tenantId = Guid.Parse("10000000-0000-0000-0000-000000000001");
        var account = IdentityAccount.Create(
            accountId,
            tenantId,
            "Lic. Mariana Paredes",
            "admin@norte.vital.demo",
            "pbkdf2-sha256$100000$aaa$bbb",
            OrgRole.ADMIN_CLINICA,
            true,
            null,
            null,
            StaffPermissions.ForAdminClinica(),
            null,
            DateTimeOffset.UtcNow);

        var now = DateTimeOffset.Parse("2026-11-21T14:00:00Z");
        var issued = issuer.IssueAccessToken(account, now);
        var jwt = new JwtSecurityTokenHandler().ReadJwtToken(issued.Token);

        Assert.Equal(accountId.ToString(), jwt.Claims.First(c => c.Type == JwtRegisteredClaimNames.Sub).Value);
        Assert.Equal("admin@norte.vital.demo", jwt.Claims.First(c => c.Type == JwtRegisteredClaimNames.Email).Value);
        Assert.Equal("ADMIN_CLINICA", jwt.Claims.First(c => c.Type == "role").Value);
        Assert.Equal(tenantId.ToString(), jwt.Claims.First(c => c.Type == "tenant_id").Value);

        var rawRefresh = issuer.GenerateRefreshToken();
        var hashA = issuer.HashRefreshToken(rawRefresh);
        var hashB = issuer.HashRefreshToken(rawRefresh);

        Assert.Equal(64, hashA.Length);
        Assert.Equal(hashA, hashB);
        Assert.NotEqual(rawRefresh, hashA);
    }
}
