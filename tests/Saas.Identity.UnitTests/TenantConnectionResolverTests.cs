using Microsoft.Extensions.Options;
using Saas.Identity.Infrastructure.Persistence.Tenancy;

namespace Saas.Identity.UnitTests;

public sealed class TenantConnectionResolverTests
{
    private sealed class StaticOptionsMonitor(TenantDatabasesOptions currentValue)
        : IOptionsMonitor<TenantDatabasesOptions>
    {
        public TenantDatabasesOptions CurrentValue => currentValue;
        public TenantDatabasesOptions Get(string? name) => currentValue;
        public IDisposable? OnChange(Action<TenantDatabasesOptions, string?> listener) => null;
    }

    [Fact]
    public void TryResolveConnectionString_SupportsConnectionsMap_AndCnpgSecretsDirectoryFormats()
    {
        var tempRoot = Path.Combine(Path.GetTempPath(), $"vital-id-secrets-{Guid.NewGuid():N}");
        Directory.CreateDirectory(tempRoot);

        try
        {
            var uriTenantId = Guid.Parse("10000000-0000-0000-0000-000000000011");
            var cnpgFilesTenantId = Guid.Parse("10000000-0000-0000-0000-000000000012");
            var mapTenantId = Guid.Parse("10000000-0000-0000-0000-000000000013");

            var uriDir = Path.Combine(tempRoot, uriTenantId.ToString("D"));
            Directory.CreateDirectory(uriDir);
            File.WriteAllText(
                Path.Combine(uriDir, "uri"),
                "postgresql://app_user:Sec%21ret1@pg-t11.internal:5432/identity_t11?sslmode=Require\n");

            var filesDir = Path.Combine(tempRoot, cnpgFilesTenantId.ToString("D"));
            Directory.CreateDirectory(filesDir);
            File.WriteAllText(Path.Combine(filesDir, "host"), "pg-t12.internal\n");
            File.WriteAllText(Path.Combine(filesDir, "port"), "5433");
            File.WriteAllText(Path.Combine(filesDir, "dbname"), "identity_t12");
            File.WriteAllText(Path.Combine(filesDir, "username"), "app_t12");
            File.WriteAllText(Path.Combine(filesDir, "password"), "pass_t12");
            File.WriteAllText(Path.Combine(filesDir, "sslmode"), "Disable");

            var resolver = new TenantConnectionResolver(new StaticOptionsMonitor(new TenantDatabasesOptions
            {
                SecretsDirectory = tempRoot,
                Connections = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                {
                    [mapTenantId.ToString("D")] = "Host=pg-t13;Port=5432;Database=identity_t13;Username=u13;Password=p13",
                },
            }));

            Assert.True(resolver.TryResolveConnectionString(uriTenantId, out var cs11));
            Assert.Contains("Host=pg-t11.internal", cs11);
            Assert.Contains("Database=identity_t11", cs11);
            Assert.Contains("SSL Mode=Require", cs11, StringComparison.OrdinalIgnoreCase);

            Assert.True(resolver.TryResolveConnectionString(cnpgFilesTenantId, out var cs12));
            Assert.Contains("Host=pg-t12.internal", cs12);
            Assert.Contains("Port=5433", cs12);
            Assert.Contains("Database=identity_t12", cs12);

            Assert.True(resolver.TryResolveConnectionString(mapTenantId, out var cs13));
            Assert.Contains("Database=identity_t13", cs13);

            Assert.False(resolver.TryResolveConnectionString(Guid.Empty, out _));
            Assert.False(resolver.TryResolveConnectionString(Guid.NewGuid(), out _));

            var configured = resolver.ListConfiguredTenantIds();
            Assert.Contains(uriTenantId, configured);
            Assert.Contains(cnpgFilesTenantId, configured);
            Assert.Contains(mapTenantId, configured);
        }
        finally
        {
            Directory.Delete(tempRoot, recursive: true);
        }
    }
}
