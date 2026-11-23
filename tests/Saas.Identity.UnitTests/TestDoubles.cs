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
    private readonly Dictionary<string, List<IdentityAccount>> _stores = new(StringComparer.Ordinal);

    public List<IdentityAccount> Items => GetStore(IdentityStoreScope.Global)
        .Concat(_stores.Where(kv => kv.Key != "global").SelectMany(kv => kv.Value))
        .ToList();

    public List<RoleAuditEntry> AuditEntries { get; } = [];

    public void Seed(IdentityAccount account)
    {
        var scope = account.TenantId is Guid tid
            ? IdentityStoreScope.ForTenant(tid)
            : IdentityStoreScope.Global;
        GetStore(scope).Add(account);
    }

    public List<IdentityAccount> GetBucket(IdentityStoreScope scope) => GetStore(scope);

    public Task<IdentityAccount?> FindByClinicEmailAsync(
        Guid tenantId,
        string normalizedEmail,
        CancellationToken cancellationToken = default) =>
        Task.FromResult(GetStore(IdentityStoreScope.ForTenant(tenantId)).FirstOrDefault(a =>
            a.TenantId == tenantId && a.NormalizedEmail == normalizedEmail));

    public Task<IdentityAccount?> FindPlatformByEmailAsync(
        string normalizedEmail,
        CancellationToken cancellationToken = default) =>
        Task.FromResult(GetStore(IdentityStoreScope.Global).FirstOrDefault(a =>
            a.TenantId is null && a.NormalizedEmail == normalizedEmail));

    public Task<IdentityAccount?> FindByIdAsync(
        IdentityStoreScope scope,
        Guid accountId,
        CancellationToken cancellationToken = default) =>
        Task.FromResult(GetStore(scope).FirstOrDefault(a =>
            a.TenantId == scope.TenantId && a.Id == accountId));

    public Task<IReadOnlyList<IdentityAccount>> ListByTenantAsync(
        Guid tenantId,
        CancellationToken cancellationToken = default) =>
        Task.FromResult<IReadOnlyList<IdentityAccount>>(
            GetStore(IdentityStoreScope.ForTenant(tenantId))
                .Where(a => a.TenantId == tenantId)
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
        Guid tenantId,
        Guid accountId,
        CancellationToken cancellationToken = default) =>
        Task.FromResult<IReadOnlyList<RoleAuditEntry>>(
            AuditEntries
                .Where(e => e.TenantId == tenantId && e.AccountId == accountId)
                .OrderByDescending(e => e.OccurredAtUtc)
                .ToList());

    public Task<int> CountActiveByTenantAsync(
        Guid tenantId,
        CancellationToken cancellationToken = default) =>
        Task.FromResult(GetStore(IdentityStoreScope.ForTenant(tenantId))
            .Count(a => a.TenantId == tenantId && a.Active));

    public Task<int> CountActiveAdminsByTenantAsync(
        Guid tenantId,
        CancellationToken cancellationToken = default) =>
        Task.FromResult(GetStore(IdentityStoreScope.ForTenant(tenantId))
            .Count(a => a.TenantId == tenantId && a.Active && a.Role == OrgRole.ADMIN_CLINICA));

    public Task AddAsync(
        IdentityStoreScope scope,
        IdentityAccount account,
        CancellationToken cancellationToken = default)
    {
        if (account.TenantId != scope.TenantId)
        {
            throw new InvalidOperationException("Mismatch de scope en InMemoryAccountRepo.AddAsync.");
        }

        GetStore(scope).Add(account);
        return Task.CompletedTask;
    }

    public Task UpdateAsync(
        IdentityStoreScope scope,
        IdentityAccount account,
        CancellationToken cancellationToken = default)
    {
        if (account.TenantId != scope.TenantId)
        {
            throw new InvalidOperationException("Mismatch de scope en InMemoryAccountRepo.UpdateAsync.");
        }

        return Task.CompletedTask;
    }

    public Task UpdateWithRoleAuditAsync(
        Guid tenantId,
        IdentityAccount account,
        RoleAuditEntry auditEntry,
        CancellationToken cancellationToken = default)
    {
        if (account.TenantId != tenantId || auditEntry.TenantId != tenantId)
        {
            throw new InvalidOperationException("Mismatch de tenant en InMemoryAccountRepo.UpdateWithRoleAuditAsync.");
        }

        AuditEntries.Add(auditEntry);
        return Task.CompletedTask;
    }

    private List<IdentityAccount> GetStore(IdentityStoreScope scope)
    {
        var key = scope.IsGlobal ? "global" : scope.TenantId!.Value.ToString("N");
        if (!_stores.TryGetValue(key, out var list))
        {
            list = [];
            _stores[key] = list;
        }

        return list;
    }
}

internal sealed class InMemoryRefreshRepo : IRefreshTokenRepository
{
    private readonly Dictionary<string, List<RefreshTokenSession>> _stores = new(StringComparer.Ordinal);

    public List<RefreshTokenSession> Sessions => _stores.Values.SelectMany(x => x).ToList();

    public void Seed(RefreshTokenSession session)
    {
        var scope = session.TenantId is Guid tid
            ? IdentityStoreScope.ForTenant(tid)
            : IdentityStoreScope.Global;
        GetStore(scope).Add(session);
    }

    public Task<RefreshTokenSession?> FindByTokenHashAsync(
        IdentityStoreScope scope,
        string tokenHash,
        CancellationToken cancellationToken = default) =>
        Task.FromResult(GetStore(scope).FirstOrDefault(s =>
            s.TenantId == scope.TenantId && s.TokenHash == tokenHash));

    public Task AddAsync(
        IdentityStoreScope scope,
        RefreshTokenSession session,
        CancellationToken cancellationToken = default)
    {
        if (session.TenantId != scope.TenantId)
        {
            throw new InvalidOperationException("Mismatch de scope en InMemoryRefreshRepo.AddAsync.");
        }

        GetStore(scope).Add(session);
        return Task.CompletedTask;
    }

    public Task UpdateAsync(
        IdentityStoreScope scope,
        RefreshTokenSession session,
        CancellationToken cancellationToken = default)
    {
        if (session.TenantId != scope.TenantId)
        {
            throw new InvalidOperationException("Mismatch de scope en InMemoryRefreshRepo.UpdateAsync.");
        }

        return Task.CompletedTask;
    }

    public Task RotateAsync(
        IdentityStoreScope scope,
        RefreshTokenSession previousSession,
        RefreshTokenSession newSession,
        CancellationToken cancellationToken = default)
    {
        if (previousSession.TenantId != scope.TenantId || newSession.TenantId != scope.TenantId)
        {
            throw new InvalidOperationException("Mismatch de scope en InMemoryRefreshRepo.RotateAsync.");
        }

        GetStore(scope).Add(newSession);
        return Task.CompletedTask;
    }

    public Task RevokeAllForAccountAsync(
        IdentityStoreScope scope,
        Guid accountId,
        DateTimeOffset revokedAtUtc,
        string reason,
        CancellationToken cancellationToken = default)
    {
        foreach (var session in GetStore(scope).Where(s => s.AccountId == accountId && !s.IsRevoked))
        {
            session.Revoke(revokedAtUtc, reason);
        }

        return Task.CompletedTask;
    }

    private List<RefreshTokenSession> GetStore(IdentityStoreScope scope)
    {
        var key = scope.IsGlobal ? "global" : scope.TenantId!.Value.ToString("N");
        if (!_stores.TryGetValue(key, out var list))
        {
            list = [];
            _stores[key] = list;
        }

        return list;
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

internal sealed class FakeTenantDatabaseMigrator : ITenantDatabaseMigratorPort
{
    public List<Guid> MigratedTenants { get; } = [];
    public bool ShouldFailUnavailable { get; set; }

    public Task EnsureMigratedAsync(Guid tenantId, CancellationToken cancellationToken = default)
    {
        if (ShouldFailUnavailable)
        {
            throw new TenantDatabaseUnavailableException(
                tenantId,
                "TENANT_DATABASE_UNAVAILABLE",
                "Simulated database failure.");
        }

        if (!MigratedTenants.Contains(tenantId))
        {
            MigratedTenants.Add(tenantId);
        }

        return Task.CompletedTask;
    }
}

internal sealed class InMemoryProvisioningRepo(InMemoryAccountRepo accounts) : IProvisioningRecordRepository
{
    private readonly SemaphoreSlim _lock = new(1, 1);

    public List<ProvisioningRecord> Records { get; } = [];

    public async Task<T> ExecuteWithTenantLockAsync<T>(
        Guid tenantId,
        Func<CancellationToken, Task<T>> action,
        CancellationToken cancellationToken = default)
    {
        await _lock.WaitAsync(cancellationToken);
        try
        {
            return await action(cancellationToken);
        }
        finally
        {
            _lock.Release();
        }
    }

    public Task<ProvisioningRecord?> FindByRequestIdAsync(
        Guid tenantId,
        string provisioningRequestId,
        CancellationToken cancellationToken = default) =>
        Task.FromResult(Records.FirstOrDefault(r =>
            r.TenantId == tenantId && r.ProvisioningRequestId == provisioningRequestId));

    public Task<ProvisioningRecord?> FindAnyByTenantAsync(
        Guid tenantId,
        CancellationToken cancellationToken = default) =>
        Task.FromResult(Records.FirstOrDefault(r => r.TenantId == tenantId));

    public Task<ProvisioningInsertOutcome> AddWithAccountAsync(
        Guid tenantId,
        ProvisioningRecord record,
        IdentityAccount account,
        CancellationToken cancellationToken = default)
    {
        if (Records.Any(r => r.TenantId == tenantId && r.ProvisioningRequestId == record.ProvisioningRequestId))
        {
            return Task.FromResult(ProvisioningInsertOutcome.DuplicateRequestId);
        }

        if (Records.Any(r => r.TenantId == tenantId))
        {
            return Task.FromResult(ProvisioningInsertOutcome.TenantAlreadyProvisioned);
        }

        if (accounts.GetBucket(IdentityStoreScope.ForTenant(tenantId))
            .Any(a => a.NormalizedEmail == account.NormalizedEmail))
        {
            return Task.FromResult(ProvisioningInsertOutcome.DuplicateEmail);
        }

        accounts.Seed(account);
        Records.Add(record);
        return Task.FromResult(ProvisioningInsertOutcome.Inserted);
    }

    public Task UpdateAsync(
        Guid tenantId,
        ProvisioningRecord record,
        CancellationToken cancellationToken = default) =>
        Task.CompletedTask;

    public Task UpdateWithAccountAsync(
        Guid tenantId,
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
