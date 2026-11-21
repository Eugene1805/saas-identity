using Saas.Identity.Domain.ValueObjects;

namespace Saas.Identity.Infrastructure.Platform;

public sealed class PlatformTenantSeedEntry
{
    public Guid TenantId { get; init; }
    public string Slug { get; init; } = string.Empty;
    public string Name { get; init; } = string.Empty;
    public TenantOperationalState State { get; init; }
    public int MaxActiveAccounts { get; init; }
}

public sealed class PlatformOptions
{
    public const string SectionName = "Platform";

    public string Mode { get; init; } = "Local";
    public string GrpcAddress { get; init; } = "http://platform-api:8092";
    public string InternalServiceKey { get; init; } = string.Empty;
    public int TimeoutSeconds { get; init; } = 3;
    public bool SimulateUnavailable { get; init; }
    public List<PlatformTenantSeedEntry> Tenants { get; init; } = [];
}
