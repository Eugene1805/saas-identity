using Saas.Identity.Domain.Entities;
using Saas.Identity.Domain.ValueObjects;

namespace Saas.Identity.Application.Ports;

public interface IAccountRepository
{
    Task<IdentityAccount?> FindByClinicEmailAsync(
        Guid tenantId,
        string normalizedEmail,
        CancellationToken cancellationToken = default);

    Task<IdentityAccount?> FindPlatformByEmailAsync(
        string normalizedEmail,
        CancellationToken cancellationToken = default);

    Task<IdentityAccount?> FindByIdAsync(
        IdentityStoreScope scope,
        Guid accountId,
        CancellationToken cancellationToken = default);

    Task<IReadOnlyList<IdentityAccount>> ListByTenantAsync(
        Guid tenantId,
        CancellationToken cancellationToken = default);

    Task<IReadOnlyDictionary<Guid, IReadOnlyList<RoleAuditEntry>>> ListRoleAuditByTenantAsync(
        Guid tenantId,
        CancellationToken cancellationToken = default);

    Task<IReadOnlyList<RoleAuditEntry>> ListRoleAuditForAccountAsync(
        Guid tenantId,
        Guid accountId,
        CancellationToken cancellationToken = default);

    Task<int> CountActiveByTenantAsync(
        Guid tenantId,
        CancellationToken cancellationToken = default);

    Task<int> CountActiveAdminsByTenantAsync(
        Guid tenantId,
        CancellationToken cancellationToken = default);

    Task AddAsync(
        IdentityStoreScope scope,
        IdentityAccount account,
        CancellationToken cancellationToken = default);

    Task UpdateAsync(
        IdentityStoreScope scope,
        IdentityAccount account,
        CancellationToken cancellationToken = default);

    Task UpdateWithRoleAuditAsync(
        Guid tenantId,
        IdentityAccount account,
        RoleAuditEntry auditEntry,
        CancellationToken cancellationToken = default);
}
