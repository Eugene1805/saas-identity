using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.IdentityModel.Tokens;
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
    public void JwtTokenIssuer_IssuesRs256ValidatedOnlyByPublicKey_PreservesClaims_AndUsesIndependentRefreshHmac()
    {
        var issuer = new JwtTokenIssuerAdapter(Microsoft.Extensions.Options.Options.Create(
            TestJwtHelper.CreateJwtOptions(accessTokenMinutes: 15, refreshTokenDays: 7)));

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

        var now = DateTimeOffset.UtcNow;
        var issued = issuer.IssueAccessToken(account, now);

        var handler = new JwtSecurityTokenHandler { MapInboundClaims = false };
        var jwt = handler.ReadJwtToken(issued.Token);

        Assert.Equal("RS256", jwt.Header.Alg);
        Assert.Equal("JWT", jwt.Header.Typ);
        Assert.Equal("saas-identity", jwt.Issuer);
        Assert.Contains("vital-saas", jwt.Audiences);
        Assert.Equal(accountId.ToString(), jwt.Claims.First(c => c.Type == JwtRegisteredClaimNames.Sub).Value);
        Assert.Equal("admin@norte.vital.demo", jwt.Claims.First(c => c.Type == JwtRegisteredClaimNames.Email).Value);
        Assert.False(string.IsNullOrWhiteSpace(jwt.Claims.First(c => c.Type == JwtRegisteredClaimNames.Jti).Value));
        Assert.False(string.IsNullOrWhiteSpace(jwt.Claims.First(c => c.Type == JwtRegisteredClaimNames.Iat).Value));
        Assert.Equal("ADMIN_CLINICA", jwt.Claims.First(c => c.Type == "role").Value);
        Assert.Equal("Lic. Mariana Paredes", jwt.Claims.First(c => c.Type == "full_name").Value);
        Assert.Equal(tenantId.ToString(), jwt.Claims.First(c => c.Type == "tenant_id").Value);

        // Validar exclusivamente con la clave pública RSA (sin clave privada).
        var validationParams = JwtCryptoMaterial.CreatePublicOnlyValidationParameters(TestJwtHelper.PublicKeyPem);
        var principal = handler.ValidateToken(issued.Token, validationParams, out var validatedToken);
        Assert.Equal(SecurityAlgorithms.RsaSha256, ((JwtSecurityToken)validatedToken).Header.Alg);
        Assert.Equal(accountId.ToString(), principal.FindFirst(JwtRegisteredClaimNames.Sub)?.Value);
        Assert.Equal("ADMIN_CLINICA", principal.FindFirst("role")?.Value);
        Assert.Equal(tenantId.ToString(), principal.FindFirst("tenant_id")?.Value);

        var rawRefresh = issuer.GenerateRefreshToken(tenantId);
        var hashA = issuer.HashRefreshToken(rawRefresh);
        var hashB = issuer.HashRefreshToken(rawRefresh);

        Assert.Equal(64, hashA.Length);
        Assert.Equal(hashA, hashB);
        Assert.NotEqual(rawRefresh, hashA);

        Assert.True(issuer.TryResolveRefreshTokenScope(rawRefresh, out var tenantScope));
        Assert.True(tenantScope.IsTenant);
        Assert.Equal(tenantId, tenantScope.TenantId);

        var globalRefresh = issuer.GenerateRefreshToken(null);
        Assert.True(issuer.TryResolveRefreshTokenScope(globalRefresh, out var globalScope));
        Assert.True(globalScope.IsGlobal);

        // Alterar el tenantId dentro del refresh token debe invalidar la firma HMAC de enrutamiento.
        var otherTenantHex = Guid.Parse("10000000-0000-0000-0000-000000000002").ToString("N");
        var tamperedTenantToken = rawRefresh.Replace(tenantId.ToString("N"), otherTenantHex, StringComparison.Ordinal);
        Assert.False(issuer.TryResolveRefreshTokenScope(tamperedTenantToken, out _));
        Assert.False(issuer.TryResolveRefreshTokenScope("random-invalid-token", out _));
    }

    [Fact]
    public void JwtTokenIssuer_SuperAdminToken_OmitsTenantIdClaim()
    {
        var issuer = TestJwtHelper.CreateJwtIssuer();
        var superAdmin = IdentityAccount.Create(
            Guid.Parse("20000000-0000-0000-0000-000000000001"),
            null,
            "SuperAdmin Vital",
            "superadmin@vital.demo",
            "pbkdf2-sha256$100000$aaa$bbb",
            OrgRole.SUPER_ADMIN,
            true,
            null,
            null,
            StaffPermissions.None,
            null,
            DateTimeOffset.UtcNow);

        var issued = issuer.IssueAccessToken(superAdmin, DateTimeOffset.UtcNow);
        var handler = new JwtSecurityTokenHandler { MapInboundClaims = false };
        var principal = handler.ValidateToken(
            issued.Token,
            JwtCryptoMaterial.CreatePublicOnlyValidationParameters(TestJwtHelper.PublicKeyPem),
            out _);

        Assert.Equal("SUPER_ADMIN", principal.FindFirst("role")?.Value);
        Assert.Null(principal.FindFirst("tenant_id"));
    }

    [Fact]
    public void PublicOnlyValidation_RejectsHs256_AlgNone_Tampered_WrongKey_Expired_AndWrongIssuerOrAudience()
    {
        var handler = new JwtSecurityTokenHandler { MapInboundClaims = false };
        var validationParams = JwtCryptoMaterial.CreatePublicOnlyValidationParameters(TestJwtHelper.PublicKeyPem);
        var now = DateTimeOffset.UtcNow;

        var account = IdentityAccount.Create(
            Guid.NewGuid(),
            Guid.NewGuid(),
            "Dra. Sofía Mendoza",
            "dra.mendoza@norte.vital.demo",
            "pbkdf2-sha256$100000$aaa$bbb",
            OrgRole.ESPECIALISTA,
            true,
            "Cardiología",
            null,
            StaffPermissions.None,
            null,
            now);

        var validToken = TestJwtHelper.CreateJwtIssuer().IssueAccessToken(account, now).Token;

        // 1. Token HS256 firmado con secreto simétrico o con los bytes de la clave pública (ataque alg confusion).
        var hs256Secret = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("ForjadoHS256SecretDeMasDe32Bytes!!"));
        var hs256Token = handler.WriteToken(new JwtSecurityToken(
            issuer: "saas-identity",
            audience: "vital-saas",
            claims: [new Claim("sub", account.Id.ToString()), new Claim("role", "SUPER_ADMIN")],
            notBefore: now.UtcDateTime,
            expires: now.AddMinutes(15).UtcDateTime,
            signingCredentials: new SigningCredentials(hs256Secret, SecurityAlgorithms.HmacSha256)));
        Assert.ThrowsAny<SecurityTokenException>(() => handler.ValidateToken(hs256Token, validationParams, out _));

        var publicPemAsHmac = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(TestJwtHelper.PublicKeyPem));
        var algConfusionToken = handler.WriteToken(new JwtSecurityToken(
            issuer: "saas-identity",
            audience: "vital-saas",
            claims: [new Claim("sub", account.Id.ToString()), new Claim("role", "SUPER_ADMIN")],
            notBefore: now.UtcDateTime,
            expires: now.AddMinutes(15).UtcDateTime,
            signingCredentials: new SigningCredentials(publicPemAsHmac, SecurityAlgorithms.HmacSha256)));
        Assert.ThrowsAny<SecurityTokenException>(() => handler.ValidateToken(algConfusionToken, validationParams, out _));

        // 2. Token sin firma (alg: none).
        var parts = validToken.Split('.');
        var noneHeader = Base64UrlEncoder.Encode("""{"alg":"none","typ":"JWT"}""");
        var unsignedToken = $"{noneHeader}.{parts[1]}.";
        Assert.ThrowsAny<SecurityTokenException>(() => handler.ValidateToken(unsignedToken, validationParams, out _));

        // 3. Token manipulado en payload o firma corrupta.
        var tamperedPayload = Base64UrlEncoder.Encode("""{"sub":"00000000-0000-0000-0000-000000000099","role":"SUPER_ADMIN"}""");
        Assert.ThrowsAny<SecurityTokenException>(() =>
            handler.ValidateToken($"{parts[0]}.{tamperedPayload}.{parts[2]}", validationParams, out _));
        Assert.ThrowsAny<SecurityTokenException>(() =>
            handler.ValidateToken($"{parts[0]}.{parts[1]}.invalid_signature", validationParams, out _));

        // 4. Token firmado con otra clave privada RSA-2048.
        using var otherRsa = RSA.Create(2048);
        var otherIssuer = new JwtTokenIssuerAdapter(Microsoft.Extensions.Options.Options.Create(
            TestJwtHelper.CreateJwtOptions(
                privateKeyPem: otherRsa.ExportPkcs8PrivateKeyPem(),
                publicKeyPem: otherRsa.ExportSubjectPublicKeyInfoPem())));
        var wrongKeyToken = otherIssuer.IssueAccessToken(account, now).Token;
        Assert.ThrowsAny<SecurityTokenException>(() => handler.ValidateToken(wrongKeyToken, validationParams, out _));

        // 5. Token expirado (> 30s de tolerancia).
        var expiredIssuer = TestJwtHelper.CreateJwtIssuer();
        var expiredToken = expiredIssuer.IssueAccessToken(account, now.AddMinutes(-20)).Token;
        Assert.Throws<SecurityTokenExpiredException>(() => handler.ValidateToken(expiredToken, validationParams, out _));

        // 6. Token con issuer o audience incorrectos (firmado con clave privada legítima).
        var material = JwtCryptoMaterial.Create(TestJwtHelper.CreateJwtOptions());
        var wrongIssuerToken = handler.WriteToken(new JwtSecurityToken(
            issuer: "otro-emisor",
            audience: "vital-saas",
            claims: [new Claim("sub", account.Id.ToString())],
            notBefore: now.UtcDateTime,
            expires: now.AddMinutes(15).UtcDateTime,
            signingCredentials: material.SigningCredentials));
        Assert.Throws<SecurityTokenInvalidIssuerException>(() =>
            handler.ValidateToken(wrongIssuerToken, validationParams, out _));

        var wrongAudienceToken = handler.WriteToken(new JwtSecurityToken(
            issuer: "saas-identity",
            audience: "otra-audiencia",
            claims: [new Claim("sub", account.Id.ToString())],
            notBefore: now.UtcDateTime,
            expires: now.AddMinutes(15).UtcDateTime,
            signingCredentials: material.SigningCredentials));
        Assert.Throws<SecurityTokenInvalidAudienceException>(() =>
            handler.ValidateToken(wrongAudienceToken, validationParams, out _));
    }

    [Fact]
    public void JwtCryptoMaterial_RejectsInvalidConfigs_AndSupportsPemFilesAndEscapedNewlines()
    {
        // Falta clave privada.
        Assert.Throws<InvalidOperationException>(() => JwtCryptoMaterial.Create(new JwtOptions
        {
            RefreshTokenHmacKey = TestJwtHelper.RefreshTokenHmacKey,
        }));

        // Clave privada inline y por ruta simultáneamente.
        Assert.Throws<InvalidOperationException>(() => JwtCryptoMaterial.Create(new JwtOptions
        {
            PrivateKeyPem = TestJwtHelper.PrivateKeyPem,
            PrivateKeyPemPath = "/tmp/nonexistent.pem",
            RefreshTokenHmacKey = TestJwtHelper.RefreshTokenHmacKey,
        }));

        // Archivo inexistente.
        Assert.Throws<InvalidOperationException>(() => JwtCryptoMaterial.Create(new JwtOptions
        {
            PrivateKeyPemPath = Path.Combine(Path.GetTempPath(), $"missing-{Guid.NewGuid():N}.pem"),
            RefreshTokenHmacKey = TestJwtHelper.RefreshTokenHmacKey,
        }));

        // PEM malformado.
        Assert.Throws<InvalidOperationException>(() => JwtCryptoMaterial.Create(
            TestJwtHelper.CreateJwtOptions(privateKeyPem: "not-a-valid-pem", publicKeyPem: "")));

        // RSA débil (1024 bits < 2048).
        using var weakRsa = RSA.Create(1024);
        Assert.Throws<InvalidOperationException>(() => JwtCryptoMaterial.Create(
            TestJwtHelper.CreateJwtOptions(
                privateKeyPem: weakRsa.ExportPkcs8PrivateKeyPem(),
                publicKeyPem: "")));

        // Clave pública colocada en PrivateKeyPem.
        Assert.Throws<InvalidOperationException>(() => JwtCryptoMaterial.Create(
            TestJwtHelper.CreateJwtOptions(
                privateKeyPem: TestJwtHelper.PublicKeyPem,
                publicKeyPem: "")));

        // Clave privada colocada en PublicKeyPem.
        Assert.Throws<InvalidOperationException>(() => JwtCryptoMaterial.Create(
            TestJwtHelper.CreateJwtOptions(
                privateKeyPem: TestJwtHelper.PrivateKeyPem,
                publicKeyPem: TestJwtHelper.PrivateKeyPem)));

        // Clave pública que no corresponde a la privada.
        using var otherRsa = RSA.Create(2048);
        Assert.Throws<InvalidOperationException>(() => JwtCryptoMaterial.Create(
            TestJwtHelper.CreateJwtOptions(
                privateKeyPem: TestJwtHelper.PrivateKeyPem,
                publicKeyPem: otherRsa.ExportSubjectPublicKeyInfoPem())));

        // Secreto HMAC ausente o corto (< 32 bytes).
        Assert.Throws<InvalidOperationException>(() => JwtCryptoMaterial.Create(
            TestJwtHelper.CreateJwtOptions(refreshTokenHmacKey: "")));
        Assert.Throws<InvalidOperationException>(() => JwtCryptoMaterial.Create(
            TestJwtHelper.CreateJwtOptions(refreshTokenHmacKey: "too-short-key")));

        // Usar la clave pública RSA como secreto HMAC debe rechazarse.
        Assert.Throws<InvalidOperationException>(() => JwtCryptoMaterial.Create(
            TestJwtHelper.CreateJwtOptions(refreshTokenHmacKey: TestJwtHelper.PublicKeyPem)));

        // Escapado de saltos de línea literal \n en PEM.
        var escapedPrivate = TestJwtHelper.PrivateKeyPem.Replace("\r\n", "\n", StringComparison.Ordinal).Replace("\n", "\\n", StringComparison.Ordinal);
        var escapedPublic = TestJwtHelper.PublicKeyPem.Replace("\r\n", "\n", StringComparison.Ordinal).Replace("\n", "\\n", StringComparison.Ordinal);
        var materialFromEscaped = JwtCryptoMaterial.Create(
            TestJwtHelper.CreateJwtOptions(privateKeyPem: escapedPrivate, publicKeyPem: escapedPublic));
        Assert.Contains("BEGIN PUBLIC KEY", materialFromEscaped.ExportPublicKeyPem(), StringComparison.Ordinal);

        // Carga desde archivos PEM temporales.
        var tempPriv = Path.GetTempFileName();
        var tempPub = Path.GetTempFileName();
        try
        {
            File.WriteAllText(tempPriv, TestJwtHelper.PrivateKeyPem);
            File.WriteAllText(tempPub, TestJwtHelper.PublicKeyPem);

            var materialFromFiles = JwtCryptoMaterial.Create(new JwtOptions
            {
                Issuer = "saas-identity",
                Audience = "vital-saas",
                PrivateKeyPemPath = tempPriv,
                PublicKeyPemPath = tempPub,
                RefreshTokenHmacKey = TestJwtHelper.RefreshTokenHmacKey,
            });
            Assert.NotNull(materialFromFiles.SigningCredentials);
        }
        finally
        {
            File.Delete(tempPriv);
            File.Delete(tempPub);
        }
    }

    [Fact]
    public void RefreshTokenRouting_IsCryptographicallyIndependentFromRsaKeyPair()
    {
        var issuerA = new JwtTokenIssuerAdapter(Microsoft.Extensions.Options.Options.Create(
            TestJwtHelper.CreateJwtOptions(refreshTokenHmacKey: "IndependentRefreshSecret_Key_0123456789!")));

        var tenantId = Guid.Parse("10000000-0000-0000-0000-000000000001");
        var refreshToken = issuerA.GenerateRefreshToken(tenantId);

        // Rotar el par RSA manteniendo el mismo secreto HMAC NO rompe el enrutamiento de refresh tokens.
        using var rotatedRsa = RSA.Create(2048);
        var issuerRotatedRsa = new JwtTokenIssuerAdapter(Microsoft.Extensions.Options.Options.Create(
            TestJwtHelper.CreateJwtOptions(
                privateKeyPem: rotatedRsa.ExportPkcs8PrivateKeyPem(),
                publicKeyPem: rotatedRsa.ExportSubjectPublicKeyInfoPem(),
                refreshTokenHmacKey: "IndependentRefreshSecret_Key_0123456789!")));

        Assert.True(issuerRotatedRsa.TryResolveRefreshTokenScope(refreshToken, out var scope));
        Assert.Equal(tenantId, scope.TenantId);

        // Cambiar el secreto HMAC invalida el tag de enrutamiento incluso con el mismo par RSA.
        var issuerDifferentHmac = new JwtTokenIssuerAdapter(Microsoft.Extensions.Options.Options.Create(
            TestJwtHelper.CreateJwtOptions(refreshTokenHmacKey: "DifferentRefreshSecret_Key_0123456789!!")));
        Assert.False(issuerDifferentHmac.TryResolveRefreshTokenScope(refreshToken, out _));
    }
}
