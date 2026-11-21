using Microsoft.Extensions.Options;
using Saas.Identity.Application.Ports;
using Saas.Identity.Domain.Common;
using Saas.Identity.Domain.ValueObjects;
using Saas.Identity.Infrastructure.Persistence;

namespace Saas.Identity.Infrastructure.Platform;

/// <summary>
/// Adaptador de salida local hasta ratificar D-01..D-04 y conectar cliente gRPC real de Platform.
/// </summary>
internal sealed class LocalTenantAccessStateAdapter(
    IOptions<PlatformOptions> optionsAccessor,
    IClockPort clock) : ITenantAccessStatePort
{
    private static readonly IReadOnlyList<PlatformTenantSeedEntry> DefaultTenants =
    [
        new()
        {
            TenantId = IdentityDbInitializer.NorteTenantId,
            Slug = "clinica-norte",
            Name = "Clínica Médica del Norte",
            State = TenantOperationalState.ACTIVA,
            MaxActiveAccounts = 8,
        },
        new()
        {
            TenantId = IdentityDbInitializer.ValleTenantId,
            Slug = "clinica-valle",
            Name = "Consultorios del Valle",
            State = TenantOperationalState.SUSPENDIDA,
            MaxActiveAccounts = 4,
        },
        new()
        {
            TenantId = IdentityDbInitializer.AuroraTenantId,
            Slug = "clinica-aurora",
            Name = "Unidad Clínica Aurora",
            State = TenantOperationalState.PENDIENTE_ADMIN,
            MaxActiveAccounts = 5,
        },
    ];

    public Task<TenantLookupResult> GetBySlugAsync(
        string clinicSlug,
        CancellationToken cancellationToken = default)
    {
        var opts = optionsAccessor.Value;
        if (opts.SimulateUnavailable)
        {
            return Task.FromResult(TenantLookupResult.Unavailable());
        }

        var normalizedSlug = clinicSlug.Trim().ToLowerInvariant();
        var match = ResolveCatalog(opts).FirstOrDefault(t =>
            t.Slug.Equals(normalizedSlug, StringComparison.OrdinalIgnoreCase));

        return Task.FromResult(match is null
            ? TenantLookupResult.NotFound()
            : TenantLookupResult.Found(ToDomainState(match)));
    }

    public Task<TenantLookupResult> GetByTenantIdAsync(
        Guid tenantId,
        CancellationToken cancellationToken = default)
    {
        var opts = optionsAccessor.Value;
        if (opts.SimulateUnavailable)
        {
            return Task.FromResult(TenantLookupResult.Unavailable());
        }

        var match = ResolveCatalog(opts).FirstOrDefault(t => t.TenantId == tenantId);
        return Task.FromResult(match is null
            ? TenantLookupResult.NotFound()
            : TenantLookupResult.Found(ToDomainState(match)));
    }

    private static IReadOnlyList<PlatformTenantSeedEntry> ResolveCatalog(PlatformOptions options) =>
        options.Tenants.Count > 0 ? options.Tenants : DefaultTenants;

    private TenantAccessState ToDomainState(PlatformTenantSeedEntry entry) =>
        new(
            entry.TenantId,
            entry.Slug,
            entry.Name,
            entry.State,
            entry.State == TenantOperationalState.ACTIVA,
            entry.MaxActiveAccounts,
            Gmt6Clock.FormatIsoGmt6(clock.UtcNow));
}
