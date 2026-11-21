using Saas.Identity.Domain.Entities;

namespace Saas.Identity.Application.Ports;

public interface IProvisioningRecordRepository
{
    Task<ProvisioningRecord?> FindByRequestIdAsync(
        string provisioningRequestId,
        CancellationToken cancellationToken = default);

    Task AddWithAccountAsync(
        ProvisioningRecord record,
        IdentityAccount account,
        CancellationToken cancellationToken = default);

    Task UpdateAsync(
        ProvisioningRecord record,
        CancellationToken cancellationToken = default);

    Task UpdateWithAccountAsync(
        ProvisioningRecord record,
        IdentityAccount account,
        CancellationToken cancellationToken = default);
}
