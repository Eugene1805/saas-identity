namespace Saas.Identity.Infrastructure.Persistence.Tenancy;

public sealed class TenantDatabasesOptions
{
    public const string SectionName = "TenantDatabases";

    public string? SecretsDirectory { get; set; }

    public Dictionary<string, string> Connections { get; set; } = new(StringComparer.OrdinalIgnoreCase);
}
