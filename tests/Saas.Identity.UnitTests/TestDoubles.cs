using Saas.Identity.Application.Ports;
using Saas.Identity.Domain.Entities;
using Saas.Identity.Domain.ValueObjects;
using Saas.Identity.Infrastructure.Security;

namespace Saas.Identity.UnitTests;

internal sealed class FakeClock(DateTimeOffset now) : IClockPort
{
    public DateTimeOffset UtcNow { get; set; } = now;
}

internal sealed class InMemoryAccountRepo : IAccountRepository
{
    public List<IdentityAccount> Items { get; } = [];
    public List<RoleAuditEntry> AuditEntries { get; } = [];

    public Task<IdentityAccount?> FindByClinicEmailAsync(
        Guid tenantId,
        string normalizedEmail,
        CancellationToken cancellationToken = default) =>
        Task.FromResult(Items.FirstOrDefault(a =>
            a.TenantId == tenantId && a.NormalizedEmail == normalizedEmail));

    public Task<IdentityAccount?> FindPlatformByEmailAsync(
        string normalizedEmail,
        CancellationToken cancellationToken = default) =>
        Task.FromResult(Items.FirstOrDefault(a =>
            a.TenantId is null && a.NormalizedEmail == normalizedEmail));

    public Task<IdentityAccount?> FindByIdAsync(
        Guid accountId,
        CancellationToken cancellationToken = default) =>
        Task.FromResult(Items.FirstOrDefault(a => a.Id == accountId));

    public Task<IReadOnlyList<IdentityAccount>> ListByTenantAsync(
        Guid tenantId,
        CancellationToken cancellationToken = default) =>
        Task.FromResult<IReadOnlyList<IdentityAccount>>(
            Items.Where(a => a.TenantId == tenantId)
                .OrderByDescending(a => a.CreatedAtUtc)
                .ToList());

    public Task<IReadOnlyDictionary<Guid, IReadOnlyList<RoleAuditEntry>>> ListRoleAuditByTenantAsync(
        Guid tenantId,
        CancellationToken cancellationToken = default)
    {
        IReadOnlyDictionary<Guid, IReadOnlyList<RoleAuditEntry>> result = AuditEntries
            .Where(e => e.TenantId == tenantId)
            .OrderByDescending(e => e.OccurredAtUtc)
            .GroupBy(e => e.AccountId)
            .ToDictionary(g => g.Key, g => (IReadOnlyList<RoleAuditEntry>)g.ToList());
        return Task.FromResult(result);
    }

    public Task<IReadOnlyList<RoleAuditEntry>> ListRoleAuditForAccountAsync(
        Guid accountId,
        CancellationToken cancellationToken = default) =>
        Task.FromResult<IReadOnlyList<RoleAuditEntry>>(
            AuditEntries
                .Where(e => e.AccountId == accountId)
                .OrderByDescending(e => e.OccurredAtUtc)
                .ToList());

    public Task<int> CountActiveByTenantAsync(
        Guid tenantId,
        CancellationToken cancellationToken = default) =>
        Task.FromResult(Items.Count(a => a.TenantId == tenantId && a.Active));

    public Task<int> CountActiveAdminsByTenantAsync(
        Guid tenantId,
        CancellationToken cancellationToken = default) =>
        Task.FromResult(Items.Count(a =>
            a.TenantId == tenantId && a.Active && a.Role == OrgRole.ADMIN_CLINICA));

    public Task AddAsync(
        IdentityAccount account,
        CancellationToken cancellationToken = default)
    {
        Items.Add(account);
        return Task.CompletedTask;
    }

    public Task UpdateAsync(
        IdentityAccount account,
        CancellationToken cancellationToken = default) =>
        Task.CompletedTask;

    public Task UpdateWithRoleAuditAsync(
        IdentityAccount account,
        RoleAuditEntry auditEntry,
        CancellationToken cancellationToken = default)
    {
        AuditEntries.Add(auditEntry);
        return Task.CompletedTask;
    }
}

internal sealed class InMemoryRefreshRepo : IRefreshTokenRepository
{
    public List<RefreshTokenSession> Sessions { get; } = [];

    public Task<RefreshTokenSession?> FindByTokenHashAsync(
        string tokenHash,
        CancellationToken cancellationToken = default) =>
        Task.FromResult(Sessions.FirstOrDefault(s => s.TokenHash == tokenHash));

    public Task AddAsync(RefreshTokenSession session, CancellationToken cancellationToken = default)
    {
        Sessions.Add(session);
        return Task.CompletedTask;
    }

    public Task UpdateAsync(RefreshTokenSession session, CancellationToken cancellationToken = default) =>
        Task.CompletedTask;

    public Task RotateAsync(
        RefreshTokenSession previousSession,
        RefreshTokenSession newSession,
        CancellationToken cancellationToken = default)
    {
        Sessions.Add(newSession);
        return Task.CompletedTask;
    }

    public Task RevokeAllForAccountAsync(
        Guid accountId,
        DateTimeOffset revokedAtUtc,
        string reason,
        CancellationToken cancellationToken = default)
    {
        foreach (var session in Sessions.Where(s => s.AccountId == accountId && !s.IsRevoked))
        {
            session.Revoke(revokedAtUtc, reason);
        }

        return Task.CompletedTask;
    }
}

internal sealed class FakeTenantPort : ITenantAccessStatePort
{
    public Dictionary<string, TenantAccessState> BySlug { get; } = new(StringComparer.OrdinalIgnoreCase);
    public bool Unavailable { get; set; }

    public Task<TenantLookupResult> GetBySlugAsync(string clinicSlug, CancellationToken cancellationToken = default)
    {
        if (Unavailable) return Task.FromResult(TenantLookupResult.Unavailable());
        return Task.FromResult(BySlug.TryGetValue(clinicSlug, out var state)
            ? TenantLookupResult.Found(state)
            : TenantLookupResult.NotFound());
    }

    public Task<TenantLookupResult> GetByTenantIdAsync(Guid tenantId, CancellationToken cancellationToken = default)
    {
        if (Unavailable) return Task.FromResult(TenantLookupResult.Unavailable());
        var state = BySlug.Values.FirstOrDefault(t => t.TenantId == tenantId);
        return Task.FromResult(state is null
            ? TenantLookupResult.NotFound()
            : TenantLookupResult.Found(state));
    }
}

internal sealed class FakeEmailDeliveryPort : ITemporaryPasswordDeliveryPort
{
    public List<TemporaryPasswordEmailMessage> SentMessages { get; } = [];
    public bool ShouldFail { get; set; }

    public Task<EmailDeliveryResult> SendTemporaryPasswordAsync(
        TemporaryPasswordEmailMessage message,
        CancellationToken cancellationToken = default)
    {
        if (ShouldFail)
        {
            return Task.FromResult(new EmailDeliveryResult(false, "EMAIL_DELIVERY_FAILED"));
        }

        SentMessages.Add(message);
        return Task.FromResult(new EmailDeliveryResult(true));
    }
}

internal sealed class InMemoryProvisioningRepo(InMemoryAccountRepo accounts) : IProvisioningRecordRepository
{
    public List<ProvisioningRecord> Records { get; } = [];

    public Task<ProvisioningRecord?> FindByRequestIdAsync(
        string provisioningRequestId,
        CancellationToken cancellationToken = default) =>
        Task.FromResult(Records.FirstOrDefault(r =>
            r.ProvisioningRequestId == provisioningRequestId));

    public Task AddWithAccountAsync(
        ProvisioningRecord record,
        IdentityAccount account,
        CancellationToken cancellationToken = default)
    {
        accounts.Items.Add(account);
        Records.Add(record);
        return Task.CompletedTask;
    }

    public Task UpdateAsync(
        ProvisioningRecord record,
        CancellationToken cancellationToken = default) =>
        Task.CompletedTask;

    public Task UpdateWithAccountAsync(
        ProvisioningRecord record,
        IdentityAccount account,
        CancellationToken cancellationToken = default) =>
        Task.CompletedTask;
}

internal static class TestJwtHelper
{
    public static JwtTokenIssuerAdapter CreateJwtIssuer() =>
        new(Microsoft.Extensions.Options.Options.Create(new JwtOptions
        {
            Issuer = "saas-identity",
            Audience = "vital-saas",
            SigningKey = "TestSigningKeyWithMoreThan32BytesForHS256!",
            AccessTokenMinutes = 15,
            RefreshTokenDays = 7,
        }));
}
