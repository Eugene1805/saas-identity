using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Grpc.Core;
using Grpc.Net.Client;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using Saas.Contracts.PlatformIdentity.V1;
using Saas.Identity.Application.UseCases.Auth;
using Saas.Identity.Application.UseCases.Staff;
using Saas.Identity.Domain.ValueObjects;
using Saas.Identity.Infrastructure.Security;
using Testcontainers.PostgreSql;

namespace Saas.Identity.IntegrationTests;

public sealed class Rs256PostgresFixture : IAsyncLifetime
{
    public static readonly Guid ClinicId = Guid.Parse("10000000-0000-0000-0000-0000000000f1");
    public const string ClinicSlug = "clinica-rs256";
    public const string InternalGrpcKey = "IntegrationTestGrpcKey_32CharsMinimum!";
    public const string RefreshTokenHmacKey = "IntegrationTestRefreshHmacKey_AtLeast32Bytes!";
    public const string SuperAdminPassword = "SuperAdminTestPass1!";

    public static readonly string JwtPrivateKeyPem;
    public static readonly string JwtPublicKeyPem;

    static Rs256PostgresFixture()
    {
        using var rsa = RSA.Create(2048);
        JwtPrivateKeyPem = rsa.ExportPkcs8PrivateKeyPem();
        JwtPublicKeyPem = rsa.ExportSubjectPublicKeyInfoPem();
    }

    private readonly List<PostgreSqlContainer> _containers = [];

    public string GlobalDbConnectionString { get; private set; } = string.Empty;
    public string TenantDbConnectionString { get; private set; } = string.Empty;

    public async Task InitializeAsync()
    {
        var extGlobal = Environment.GetEnvironmentVariable("TEST_RS256_GLOBAL_DB_CS");
        var extTenant = Environment.GetEnvironmentVariable("TEST_RS256_TENANT_DB_CS");
        if (!string.IsNullOrWhiteSpace(extGlobal) && !string.IsNullOrWhiteSpace(extTenant))
        {
            GlobalDbConnectionString = extGlobal;
            TenantDbConnectionString = extTenant;
            return;
        }

        var globalContainer = new PostgreSqlBuilder("postgres:17-alpine")
            .WithDatabase("identity_rs256_global")
            .WithUsername("global_u")
            .WithPassword("global_p")
            .Build();
        var tenantContainer = new PostgreSqlBuilder("postgres:17-alpine")
            .WithDatabase("identity_rs256_clinic")
            .WithUsername("clinic_u")
            .WithPassword("clinic_p")
            .Build();

        _containers.AddRange([globalContainer, tenantContainer]);
        await Task.WhenAll(_containers.Select(c => c.StartAsync()));

        GlobalDbConnectionString = globalContainer.GetConnectionString();
        TenantDbConnectionString = tenantContainer.GetConnectionString();
    }

    public WebApplicationFactory<Program> CreateFactory(IDictionary<string, string?>? configOverrides = null)
    {
        return new WebApplicationFactory<Program>().WithWebHostBuilder(builder =>
        {
            builder.UseEnvironment("Development");

            var settings = new Dictionary<string, string?>
            {
                ["ConnectionStrings:IdentityGlobalDb"] = GlobalDbConnectionString,
                [$"TenantDatabases:Connections:{ClinicId}"] = TenantDbConnectionString,
                ["Jwt:Issuer"] = "saas-identity",
                ["Jwt:Audience"] = "vital-saas",
                ["Jwt:PrivateKeyPem"] = JwtPrivateKeyPem,
                ["Jwt:PublicKeyPem"] = JwtPublicKeyPem,
                ["Jwt:RefreshTokenHmacKey"] = RefreshTokenHmacKey,
                ["InternalGrpc:ApiKey"] = InternalGrpcKey,
                ["Email:Mode"] = "LogOnly",
                ["Platform:Mode"] = "Local",
                ["SeedDemoData"] = "true",
                ["DemoSeed:Password"] = SuperAdminPassword,
                ["OpenApi:Enabled"] = "false",
                ["Platform:Tenants:0:TenantId"] = ClinicId.ToString(),
                ["Platform:Tenants:0:Slug"] = ClinicSlug,
                ["Platform:Tenants:0:Name"] = "Clínica RS256",
                ["Platform:Tenants:0:State"] = "ACTIVA",
                ["Platform:Tenants:0:MaxActiveAccounts"] = "8",
            };

            if (configOverrides is not null)
            {
                foreach (var kv in configOverrides)
                {
                    settings[kv.Key] = kv.Value;
                }
            }

            foreach (var kv in settings)
            {
                builder.UseSetting(kv.Key, kv.Value);
            }
        });
    }

    public async Task DisposeAsync()
    {
        await Task.WhenAll(_containers.Select(c => c.DisposeAsync().AsTask()));
    }
}

public sealed class JwtRs256IntegrationTests(Rs256PostgresFixture fixture)
    : IClassFixture<Rs256PostgresFixture>
{
    [Fact]
    public async Task LoginClinicAndSuperAdmin_EmitRs256Tokens_ValidatedByPublicKeyOnly_AndEnforceStrictRejection()
    {
        await using var factory = fixture.CreateFactory();
        var client = factory.CreateDefaultClient();

        using var channel = GrpcChannel.ForAddress(
            client.BaseAddress!,
            new GrpcChannelOptions { HttpClient = client });
        var grpcClient = new IdentityProvisioningService.IdentityProvisioningServiceClient(channel);
        var grpcHeaders = new Metadata
        {
            { "x-internal-service-key", Rs256PostgresFixture.InternalGrpcKey },
        };

        var prov = await grpcClient.ProvisionInitialClinicAdminAsync(
            new ProvisionInitialClinicAdminRequest
            {
                TenantId = Rs256PostgresFixture.ClinicId.ToString(),
                ProvisioningRequestId = $"prov-rs256-{Guid.NewGuid():N}",
                ClinicSlug = Rs256PostgresFixture.ClinicSlug,
                ClinicName = "Clínica RS256",
                AdminFullName = "Admin RS256",
                AdminEmail = "admin@rs256.vital.demo",
            },
            grpcHeaders);
        Assert.Equal(ProvisioningStatus.Ready, prov.Status);

        const string email = "dr.rs256@vital.demo";
        const string password = "Rs256TestPass!2026";
        var adminId = Guid.Parse(prov.InitialAdminAccountId);

        using (var scope = factory.Services.CreateScope())
        {
            var createStaff = scope.ServiceProvider.GetRequiredService<CreateStaffUseCase>();
            var created = await createStaff.ExecuteAsync(new CreateStaffCommand(
                IdentityStoreScope.ForTenant(Rs256PostgresFixture.ClinicId),
                adminId,
                "Dr. Prueba RS256",
                email,
                password,
                GenerateTemporaryPassword: false,
                "ESPECIALISTA",
                "Cardiología",
                "CED-RS256-01",
                "Cardiólogo",
                new StaffPermissions(true, true, false, false)));
            Assert.True(created.IsSuccess);
        }

        // 1. Login clínico emite RS256 con claims esperados y se valida usando SOLO clave pública.
        var clinicLoginResp = await client.PostAsJsonAsync("/v1/auth/login", new
        {
            clinicSlug = Rs256PostgresFixture.ClinicSlug,
            email,
            password,
        });
        Assert.Equal(HttpStatusCode.OK, clinicLoginResp.StatusCode);
        var clinicSession = await clinicLoginResp.Content.ReadFromJsonAsync<AuthSessionResult>();
        Assert.NotNull(clinicSession);

        var handler = new JwtSecurityTokenHandler { MapInboundClaims = false };
        var publicOnlyParams = JwtCryptoMaterial.CreatePublicOnlyValidationParameters(Rs256PostgresFixture.JwtPublicKeyPem);
        var clinicPrincipal = handler.ValidateToken(clinicSession!.AccessToken, publicOnlyParams, out var clinicValidatedToken);
        var clinicJwt = Assert.IsType<JwtSecurityToken>(clinicValidatedToken);

        Assert.Equal("RS256", clinicJwt.Header.Alg);
        Assert.Equal("saas-identity", clinicJwt.Issuer);
        Assert.Contains("vital-saas", clinicJwt.Audiences);
        Assert.Equal(clinicSession.Account.Id.ToString(), clinicPrincipal.FindFirstValue(JwtRegisteredClaimNames.Sub));
        Assert.Equal(email, clinicPrincipal.FindFirstValue(JwtRegisteredClaimNames.Email));
        Assert.Equal("ESPECIALISTA", clinicPrincipal.FindFirstValue("role"));
        Assert.Equal("Dr. Prueba RS256", clinicPrincipal.FindFirstValue("full_name"));
        Assert.Equal(Rs256PostgresFixture.ClinicId.ToString(), clinicPrincipal.FindFirstValue("tenant_id"));
        Assert.False(string.IsNullOrWhiteSpace(clinicPrincipal.FindFirstValue(JwtRegisteredClaimNames.Jti)));
        Assert.False(string.IsNullOrWhiteSpace(clinicPrincipal.FindFirstValue(JwtRegisteredClaimNames.Iat)));

        using (var meReq = new HttpRequestMessage(HttpMethod.Get, "/v1/auth/me"))
        {
            meReq.Headers.Authorization = new AuthenticationHeaderValue("Bearer", clinicSession.AccessToken);
            var meResp = await client.SendAsync(meReq);
            Assert.Equal(HttpStatusCode.OK, meResp.StatusCode);
        }

        // 2. Login SuperAdmin emite RS256 sin tenant_id.
        var superLoginResp = await client.PostAsJsonAsync("/v1/auth/platform/login", new
        {
            email = "superadmin@vital.demo",
            password = Rs256PostgresFixture.SuperAdminPassword,
        });
        Assert.Equal(HttpStatusCode.OK, superLoginResp.StatusCode);
        var superSession = await superLoginResp.Content.ReadFromJsonAsync<AuthSessionResult>();
        Assert.NotNull(superSession);

        var superPrincipal = handler.ValidateToken(superSession!.AccessToken, publicOnlyParams, out var superValidatedToken);
        Assert.Equal("RS256", ((JwtSecurityToken)superValidatedToken).Header.Alg);
        Assert.Equal("SUPER_ADMIN", superPrincipal.FindFirstValue("role"));
        Assert.Null(superPrincipal.FindFirst("tenant_id"));

        // 3. Rechazo HTTP (401) para tokens HS256, alg:none, manipulados, otra clave, expirados, iss/aud inválidos y SUPER_ADMIN con tenant_id.
        var now = DateTimeOffset.UtcNow;
        var privateMaterial = JwtCryptoMaterial.Create(new JwtOptions
        {
            Issuer = "saas-identity",
            Audience = "vital-saas",
            PrivateKeyPem = Rs256PostgresFixture.JwtPrivateKeyPem,
            PublicKeyPem = Rs256PostgresFixture.JwtPublicKeyPem,
            RefreshTokenHmacKey = Rs256PostgresFixture.RefreshTokenHmacKey,
        });

        var baseClaims = new[]
        {
            new Claim(JwtRegisteredClaimNames.Sub, superSession.Account.Id.ToString()),
            new Claim(JwtRegisteredClaimNames.Email, "superadmin@vital.demo"),
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            new Claim(JwtRegisteredClaimNames.Iat, now.ToUnixTimeSeconds().ToString(), ClaimValueTypes.Integer64),
            new Claim("role", "SUPER_ADMIN"),
            new Claim("full_name", "SuperAdmin"),
        };

        var hs256Token = handler.WriteToken(new JwtSecurityToken(
            issuer: "saas-identity",
            audience: "vital-saas",
            claims: baseClaims,
            notBefore: now.UtcDateTime,
            expires: now.AddMinutes(15).UtcDateTime,
            signingCredentials: new SigningCredentials(
                new SymmetricSecurityKey(Encoding.UTF8.GetBytes("ForjadoHS256SecretAtLeast32BytesLong!")),
                SecurityAlgorithms.HmacSha256)));
        Assert.Equal(HttpStatusCode.Unauthorized, await GetMeStatusAsync(client, hs256Token));

        var algConfusionToken = handler.WriteToken(new JwtSecurityToken(
            issuer: "saas-identity",
            audience: "vital-saas",
            claims: baseClaims,
            notBefore: now.UtcDateTime,
            expires: now.AddMinutes(15).UtcDateTime,
            signingCredentials: new SigningCredentials(
                new SymmetricSecurityKey(Encoding.UTF8.GetBytes(Rs256PostgresFixture.JwtPublicKeyPem)),
                SecurityAlgorithms.HmacSha256)));
        Assert.Equal(HttpStatusCode.Unauthorized, await GetMeStatusAsync(client, algConfusionToken));

        var validParts = superSession.AccessToken.Split('.');
        var unsignedToken = $"{Base64UrlEncoder.Encode("""{"alg":"none","typ":"JWT"}""")}.{validParts[1]}.";
        Assert.Equal(HttpStatusCode.Unauthorized, await GetMeStatusAsync(client, unsignedToken));
        Assert.Equal(HttpStatusCode.Unauthorized, await GetMeStatusAsync(client, $"{validParts[0]}.{validParts[1]}.corrupted_sig"));

        using var rogueRsa = RSA.Create(2048);
        var rogueCreds = new SigningCredentials(new RsaSecurityKey(rogueRsa.ExportParameters(true)), SecurityAlgorithms.RsaSha256);
        var rogueToken = handler.WriteToken(new JwtSecurityToken(
            issuer: "saas-identity",
            audience: "vital-saas",
            claims: baseClaims,
            notBefore: now.UtcDateTime,
            expires: now.AddMinutes(15).UtcDateTime,
            signingCredentials: rogueCreds));
        Assert.Equal(HttpStatusCode.Unauthorized, await GetMeStatusAsync(client, rogueToken));

        var expiredToken = handler.WriteToken(new JwtSecurityToken(
            issuer: "saas-identity",
            audience: "vital-saas",
            claims: baseClaims,
            notBefore: now.AddMinutes(-20).UtcDateTime,
            expires: now.AddMinutes(-2).UtcDateTime,
            signingCredentials: privateMaterial.SigningCredentials));
        Assert.Equal(HttpStatusCode.Unauthorized, await GetMeStatusAsync(client, expiredToken));

        var wrongIssToken = handler.WriteToken(new JwtSecurityToken(
            issuer: "wrong-issuer",
            audience: "vital-saas",
            claims: baseClaims,
            notBefore: now.UtcDateTime,
            expires: now.AddMinutes(15).UtcDateTime,
            signingCredentials: privateMaterial.SigningCredentials));
        Assert.Equal(HttpStatusCode.Unauthorized, await GetMeStatusAsync(client, wrongIssToken));

        var wrongAudToken = handler.WriteToken(new JwtSecurityToken(
            issuer: "saas-identity",
            audience: "wrong-audience",
            claims: baseClaims,
            notBefore: now.UtcDateTime,
            expires: now.AddMinutes(15).UtcDateTime,
            signingCredentials: privateMaterial.SigningCredentials));
        Assert.Equal(HttpStatusCode.Unauthorized, await GetMeStatusAsync(client, wrongAudToken));

        var superWithTenantToken = handler.WriteToken(new JwtSecurityToken(
            issuer: "saas-identity",
            audience: "vital-saas",
            claims: [.. baseClaims, new Claim("tenant_id", Rs256PostgresFixture.ClinicId.ToString())],
            notBefore: now.UtcDateTime,
            expires: now.AddMinutes(15).UtcDateTime,
            signingCredentials: privateMaterial.SigningCredentials));
        Assert.Equal(HttpStatusCode.Unauthorized, await GetMeStatusAsync(client, superWithTenantToken));
    }

    [Fact]
    public async Task Startup_FailsClosed_OnInvalidRs256OrLegacyHs256Configuration()
    {
        using var weakRsa = RSA.Create(1024);
        using var otherRsa = RSA.Create(2048);

        var badConfigs = new Dictionary<string, string?>[]
        {
            new() { ["Jwt:PrivateKeyPem"] = "", ["Jwt:PrivateKeyPemPath"] = "" },
            new() { ["Jwt:PrivateKeyPem"] = "invalid-pem-content" },
            new() { ["Jwt:PrivateKeyPem"] = weakRsa.ExportPkcs8PrivateKeyPem(), ["Jwt:PublicKeyPem"] = "" },
            new() { ["Jwt:PublicKeyPem"] = otherRsa.ExportSubjectPublicKeyInfoPem() },
            new() { ["Jwt:RefreshTokenHmacKey"] = "short" },
            new() { ["Jwt:SigningKey"] = "LegacyHs256KeyWithMoreThan32Bytes_MustFail!" },
        };

        foreach (var overrides in badConfigs)
        {
            await using var badFactory = fixture.CreateFactory(configOverrides: overrides);
            Assert.Throws<InvalidOperationException>(() => badFactory.CreateDefaultClient());
        }
    }

    private static async Task<HttpStatusCode> GetMeStatusAsync(HttpClient client, string bearerToken)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, "/v1/auth/me");
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", bearerToken);
        using var response = await client.SendAsync(request);
        return response.StatusCode;
    }
}
