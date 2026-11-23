using Saas.Identity.Domain.Entities;

namespace Saas.Identity.Application.Ports;

public enum ProvisioningInsertOutcome
{
    Inserted = 1,
    DuplicateRequestId = 2,
    TenantAlreadyProvisioned = 3,
    DuplicateEmail = 4,
}

public interface IProvisioningRecordRepository
{
    Task<T> ExecuteWithTenantLockAsync<T>(
        Guid tenantId,
        Func<CancellationToken, Task<T>> action,
        CancellationToken cancellationToken = default);

    Task<ProvisioningRecord?> FindByRequestIdAsync(
        Guid tenantId,
        string provisioningRequestId,
        CancellationToken cancellationToken = default);

    Task<ProvisioningRecord?> FindAnyByTenantAsync(
        Guid tenantId,
        CancellationToken cancellationToken = default);

    Task<ProvisioningInsertOutcome> AddWithAccountAsync(
        Guid tenantId,
        ProvisioningRecord record,
        IdentityAccount account,
        CancellationToken cancellationToken = default);

    Task UpdateAsync(
        Guid tenantId,
        ProvisioningRecord record,
        CancellationToken cancellationToken = default);

    Task UpdateWithAccountAsync(
        Guid tenantId,
        ProvisioningRecord record,
        IdentityAccount account,
        CancellationToken cancellationToken = default);
}
