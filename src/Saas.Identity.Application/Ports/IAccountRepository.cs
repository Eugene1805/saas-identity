using Saas.Identity.Domain.Entities;

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
        Guid accountId,
        CancellationToken cancellationToken = default);

    Task<IReadOnlyList<IdentityAccount>> ListByTenantAsync(
        Guid tenantId,
        CancellationToken cancellationToken = default);

    Task<IReadOnlyDictionary<Guid, IReadOnlyList<RoleAuditEntry>>> ListRoleAuditByTenantAsync(
        Guid tenantId,
        CancellationToken cancellationToken = default);

    Task<IReadOnlyList<RoleAuditEntry>> ListRoleAuditForAccountAsync(
        Guid accountId,
        CancellationToken cancellationToken = default);

    Task<int> CountActiveByTenantAsync(
        Guid tenantId,
        CancellationToken cancellationToken = default);

    Task<int> CountActiveAdminsByTenantAsync(
        Guid tenantId,
        CancellationToken cancellationToken = default);

    Task AddAsync(
        IdentityAccount account,
        CancellationToken cancellationToken = default);

    Task UpdateAsync(
        IdentityAccount account,
        CancellationToken cancellationToken = default);

    Task UpdateWithRoleAuditAsync(
        IdentityAccount account,
        RoleAuditEntry auditEntry,
        CancellationToken cancellationToken = default);
}
