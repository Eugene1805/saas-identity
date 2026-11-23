using Microsoft.Extensions.Options;
using Npgsql;

namespace Saas.Identity.Infrastructure.Persistence.Tenancy;

public sealed class TenantConnectionResolver(IOptionsMonitor<TenantDatabasesOptions> optionsMonitor)
    : ITenantConnectionResolver
{
    public bool TryResolveConnectionString(Guid tenantId, out string connectionString)
    {
        connectionString = string.Empty;
        if (tenantId == Guid.Empty)
        {
            return false;
        }

        var opts = optionsMonitor.CurrentValue;

        if (!string.IsNullOrWhiteSpace(opts.SecretsDirectory) && Directory.Exists(opts.SecretsDirectory))
        {
            if (TryResolveFromSecretsDirectory(opts.SecretsDirectory, tenantId, out connectionString))
            {
                return true;
            }
        }

        foreach (var entry in opts.Connections)
        {
            if (Guid.TryParse(entry.Key, out var configuredTenantId) &&
                configuredTenantId == tenantId &&
                !string.IsNullOrWhiteSpace(entry.Value))
            {
                connectionString = NormalizeConnectionString(entry.Value);
                return !string.IsNullOrWhiteSpace(connectionString);
            }
        }

        return false;
    }

    public IReadOnlyCollection<Guid> ListConfiguredTenantIds()
    {
        var opts = optionsMonitor.CurrentValue;
        var ids = new HashSet<Guid>();

        if (!string.IsNullOrWhiteSpace(opts.SecretsDirectory) && Directory.Exists(opts.SecretsDirectory))
        {
            foreach (var dir in Directory.GetDirectories(opts.SecretsDirectory))
            {
                if (Guid.TryParse(Path.GetFileName(dir), out var dirTenantId) && dirTenantId != Guid.Empty)
                {
                    ids.Add(dirTenantId);
                }
            }

            foreach (var file in Directory.GetFiles(opts.SecretsDirectory))
            {
                var stem = Path.GetFileNameWithoutExtension(file);
                if (Guid.TryParse(stem, out var fileTenantId) && fileTenantId != Guid.Empty)
                {
                    ids.Add(fileTenantId);
                }
            }
        }

        foreach (var entry in opts.Connections)
        {
            if (Guid.TryParse(entry.Key, out var tenantId) &&
                tenantId != Guid.Empty &&
                !string.IsNullOrWhiteSpace(entry.Value))
            {
                ids.Add(tenantId);
            }
        }

        return ids;
    }

    internal static string NormalizeConnectionString(string raw)
    {
        var trimmed = raw.Trim();
        if (string.IsNullOrEmpty(trimmed))
        {
            return string.Empty;
        }

        if (trimmed.StartsWith("postgres://", StringComparison.OrdinalIgnoreCase) ||
            trimmed.StartsWith("postgresql://", StringComparison.OrdinalIgnoreCase))
        {
            var uri = new Uri(trimmed);
            var builder = new NpgsqlConnectionStringBuilder
            {
                Host = uri.Host,
                Port = uri.Port > 0 ? uri.Port : 5432,
                Database = Uri.UnescapeDataString(uri.AbsolutePath.TrimStart('/')),
            };

            if (!string.IsNullOrEmpty(uri.UserInfo))
            {
                var separatorIndex = uri.UserInfo.IndexOf(':');
                if (separatorIndex >= 0)
                {
                    builder.Username = Uri.UnescapeDataString(uri.UserInfo[..separatorIndex]);
                    builder.Password = Uri.UnescapeDataString(uri.UserInfo[(separatorIndex + 1)..]);
                }
                else
                {
                    builder.Username = Uri.UnescapeDataString(uri.UserInfo);
                }
            }

            if (!string.IsNullOrEmpty(uri.Query))
            {
                foreach (var pair in uri.Query.TrimStart('?').Split('&', StringSplitOptions.RemoveEmptyEntries))
                {
                    var eq = pair.IndexOf('=');
                    if (eq <= 0)
                    {
                        continue;
                    }

                    var key = Uri.UnescapeDataString(pair[..eq]);
                    var value = Uri.UnescapeDataString(pair[(eq + 1)..]);
                    if (key.Equals("sslmode", StringComparison.OrdinalIgnoreCase) &&
                        Enum.TryParse<SslMode>(value, ignoreCase: true, out var sslMode))
                    {
                        builder.SslMode = sslMode;
                    }
                }
            }

            return builder.ConnectionString;
        }

        return new NpgsqlConnectionStringBuilder(trimmed).ConnectionString;
    }

    private static bool TryResolveFromSecretsDirectory(
        string secretsDirectory,
        Guid tenantId,
        out string connectionString)
    {
        connectionString = string.Empty;
        var canonicalId = tenantId.ToString("D");

        foreach (var suffix in new[] { ".connection", ".txt" })
        {
            var filePath = Path.Combine(secretsDirectory, canonicalId + suffix);
            if (File.Exists(filePath))
            {
                var content = File.ReadAllText(filePath);
                if (!string.IsNullOrWhiteSpace(content))
                {
                    connectionString = NormalizeConnectionString(content);
                    return !string.IsNullOrWhiteSpace(connectionString);
                }
            }
        }

        var tenantDir = Path.Combine(secretsDirectory, canonicalId);
        if (!Directory.Exists(tenantDir))
        {
            return false;
        }

        foreach (var singleKey in new[] { "uri", "connectionString", "connection" })
        {
            var uriPath = Path.Combine(tenantDir, singleKey);
            if (File.Exists(uriPath))
            {
                var rawUri = File.ReadAllText(uriPath);
                if (!string.IsNullOrWhiteSpace(rawUri))
                {
                    connectionString = NormalizeConnectionString(rawUri);
                    return !string.IsNullOrWhiteSpace(connectionString);
                }
            }
        }

        var host = ReadOptionalSecretFile(tenantDir, "host");
        var database = ReadOptionalSecretFile(tenantDir, "dbname") ?? ReadOptionalSecretFile(tenantDir, "database");
        var username = ReadOptionalSecretFile(tenantDir, "username") ?? ReadOptionalSecretFile(tenantDir, "user");
        var password = ReadOptionalSecretFile(tenantDir, "password");

        if (string.IsNullOrWhiteSpace(host) ||
            string.IsNullOrWhiteSpace(database) ||
            string.IsNullOrWhiteSpace(username) ||
            string.IsNullOrWhiteSpace(password))
        {
            return false;
        }

        var builder = new NpgsqlConnectionStringBuilder
        {
            Host = host,
            Port = int.TryParse(ReadOptionalSecretFile(tenantDir, "port"), out var parsedPort) && parsedPort > 0
                ? parsedPort
                : 5432,
            Database = database,
            Username = username,
            Password = password,
        };

        var sslText = ReadOptionalSecretFile(tenantDir, "sslmode");
        if (!string.IsNullOrWhiteSpace(sslText) &&
            Enum.TryParse<SslMode>(sslText, ignoreCase: true, out var sslMode))
        {
            builder.SslMode = sslMode;
        }

        connectionString = builder.ConnectionString;
        return true;
    }

    private static string? ReadOptionalSecretFile(string directory, string fileName)
    {
        var path = Path.Combine(directory, fileName);
        if (!File.Exists(path))
        {
            return null;
        }

        var text = File.ReadAllText(path).Trim();
        return string.IsNullOrEmpty(text) ? null : text;
    }
}
