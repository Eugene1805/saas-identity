using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Testcontainers.PostgreSql;

namespace Saas.Identity.IntegrationTests;

public sealed class MultiPostgresFixture : IAsyncLifetime
{
    public static readonly Guid ClinicAId = Guid.Parse("10000000-0000-0000-0000-0000000000a1");
    public static readonly Guid ClinicBId = Guid.Parse("10000000-0000-0000-0000-0000000000b2");
    public static readonly Guid ClinicNewId = Guid.Parse("10000000-0000-0000-0000-0000000000c3");
    public static readonly Guid ClinicRaceId = Guid.Parse("10000000-0000-0000-0000-0000000000d4");

    public const string ClinicASlug = "clinica-alfa";
    public const string ClinicBSlug = "clinica-beta";
    public const string ClinicNewSlug = "clinica-nueva";
    public const string ClinicRaceSlug = "clinica-carrera";

    public const string InternalGrpcKey = "IntegrationTestGrpcKey_32CharsMinimum!";
    public const string JwtSigningKey = "IntegrationTestJwtSigningKey_AtLeast32Bytes!";
    public const string SuperAdminPassword = "SuperAdminTestPass1!";

    private readonly List<PostgreSqlContainer> _containers = [];

    public string GlobalDbConnectionString { get; private set; } = string.Empty;
    public string TenantADbConnectionString { get; private set; } = string.Empty;
    public string TenantBDbConnectionString { get; private set; } = string.Empty;
    public string TenantNewDbConnectionString { get; private set; } = string.Empty;
    public string TenantRaceDbConnectionString { get; private set; } = string.Empty;

    public async Task InitializeAsync()
    {
        var extGlobal = Environment.GetEnvironmentVariable("TEST_GLOBAL_DB_CS");
        var extA = Environment.GetEnvironmentVariable("TEST_TENANT_A_DB_CS");
        var extB = Environment.GetEnvironmentVariable("TEST_TENANT_B_DB_CS");
        var extNew = Environment.GetEnvironmentVariable("TEST_TENANT_NEW_DB_CS");
        var extRace = Environment.GetEnvironmentVariable("TEST_TENANT_RACE_DB_CS");

        if (!string.IsNullOrWhiteSpace(extGlobal) &&
            !string.IsNullOrWhiteSpace(extA) &&
            !string.IsNullOrWhiteSpace(extB) &&
            !string.IsNullOrWhiteSpace(extNew) &&
            !string.IsNullOrWhiteSpace(extRace))
        {
            GlobalDbConnectionString = extGlobal;
            TenantADbConnectionString = extA;
            TenantBDbConnectionString = extB;
            TenantNewDbConnectionString = extNew;
            TenantRaceDbConnectionString = extRace;
            return;
        }

        var globalContainer = BuildPostgres("identity_global", "global_u", "global_p");
        var tenantAContainer = BuildPostgres("identity_alfa", "alfa_u", "alfa_p");
        var tenantBContainer = BuildPostgres("identity_beta", "beta_u", "beta_p");
        var tenantNewContainer = BuildPostgres("identity_nueva", "nueva_u", "nueva_p");
        var tenantRaceContainer = BuildPostgres("identity_carrera", "carrera_u", "carrera_p");

        _containers.AddRange([globalContainer, tenantAContainer, tenantBContainer, tenantNewContainer, tenantRaceContainer]);
        await Task.WhenAll(_containers.Select(c => c.StartAsync()));

        GlobalDbConnectionString = globalContainer.GetConnectionString();
        TenantADbConnectionString = tenantAContainer.GetConnectionString();
        TenantBDbConnectionString = tenantBContainer.GetConnectionString();
        TenantNewDbConnectionString = tenantNewContainer.GetConnectionString();
        TenantRaceDbConnectionString = tenantRaceContainer.GetConnectionString();
    }

    public WebApplicationFactory<Program> CreateFactory(string? overrideGrpcApiKey = InternalGrpcKey)
    {
        return new WebApplicationFactory<Program>().WithWebHostBuilder(builder =>
        {
            builder.UseEnvironment("Development");

            var settings = new Dictionary<string, string?>
            {
                ["ConnectionStrings:IdentityGlobalDb"] = GlobalDbConnectionString,
                [$"TenantDatabases:Connections:{ClinicAId}"] = TenantADbConnectionString,
                [$"TenantDatabases:Connections:{ClinicBId}"] = TenantBDbConnectionString,
                [$"TenantDatabases:Connections:{ClinicNewId}"] = TenantNewDbConnectionString,
                [$"TenantDatabases:Connections:{ClinicRaceId}"] = TenantRaceDbConnectionString,
                ["Jwt:Issuer"] = "saas-identity",
                ["Jwt:Audience"] = "vital-saas",
                ["Jwt:SigningKey"] = JwtSigningKey,
                ["InternalGrpc:ApiKey"] = overrideGrpcApiKey,
                ["Email:Mode"] = "LogOnly",
                ["Platform:Mode"] = "Local",
                ["SeedDemoData"] = "true",
                ["DemoSeed:Password"] = SuperAdminPassword,
                ["OpenApi:Enabled"] = "false",

                ["Platform:Tenants:0:TenantId"] = ClinicAId.ToString(),
                ["Platform:Tenants:0:Slug"] = ClinicASlug,
                ["Platform:Tenants:0:Name"] = "Clínica Alfa",
                ["Platform:Tenants:0:State"] = "ACTIVA",
                ["Platform:Tenants:0:MaxActiveAccounts"] = "8",

                ["Platform:Tenants:1:TenantId"] = ClinicBId.ToString(),
                ["Platform:Tenants:1:Slug"] = ClinicBSlug,
                ["Platform:Tenants:1:Name"] = "Clínica Beta",
                ["Platform:Tenants:1:State"] = "ACTIVA",
                ["Platform:Tenants:1:MaxActiveAccounts"] = "8",

                ["Platform:Tenants:2:TenantId"] = ClinicNewId.ToString(),
                ["Platform:Tenants:2:Slug"] = ClinicNewSlug,
                ["Platform:Tenants:2:Name"] = "Clínica Nueva",
                ["Platform:Tenants:2:State"] = "PENDIENTE_ADMIN",
                ["Platform:Tenants:2:MaxActiveAccounts"] = "5",

                ["Platform:Tenants:3:TenantId"] = ClinicRaceId.ToString(),
                ["Platform:Tenants:3:Slug"] = ClinicRaceSlug,
                ["Platform:Tenants:3:Name"] = "Clínica Carrera",
                ["Platform:Tenants:3:State"] = "PENDIENTE_ADMIN",
                ["Platform:Tenants:3:MaxActiveAccounts"] = "5",
            };

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

    private static PostgreSqlContainer BuildPostgres(string database, string username, string password) =>
        new PostgreSqlBuilder("postgres:17-alpine")
            .WithDatabase(database)
            .WithUsername(username)
            .WithPassword(password)
            .Build();
}
