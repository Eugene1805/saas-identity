using Saas.Identity.Domain.ValueObjects;

namespace Saas.Identity.Application.Ports;

public sealed record TenantLookupResult(
    bool PlatformUnavailable,
    TenantAccessState? Tenant)
{
    public static TenantLookupResult Found(TenantAccessState tenant) => new(false, tenant);
    public static TenantLookupResult NotFound() => new(false, null);
    public static TenantLookupResult Unavailable() => new(true, null);
}

public interface ITenantAccessStatePort
{
    Task<TenantLookupResult> GetBySlugAsync(
        string clinicSlug,
        CancellationToken cancellationToken = default);

    Task<TenantLookupResult> GetByTenantIdAsync(
        Guid tenantId,
        CancellationToken cancellationToken = default);
}
