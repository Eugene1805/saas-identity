using Microsoft.EntityFrameworkCore;
using Saas.Identity.Application.Ports;
using Saas.Identity.Domain.Entities;

namespace Saas.Identity.Infrastructure.Persistence.Repositories;

internal sealed class EfProvisioningRecordRepository(IdentityDbContext dbContext)
    : IProvisioningRecordRepository
{
    public Task<ProvisioningRecord?> FindByRequestIdAsync(
        string provisioningRequestId,
        CancellationToken cancellationToken = default)
    {
        return dbContext.ProvisioningRecords.FirstOrDefaultAsync(
            p => p.ProvisioningRequestId == provisioningRequestId,
            cancellationToken);
    }

    public async Task AddWithAccountAsync(
        ProvisioningRecord record,
        IdentityAccount account,
        CancellationToken cancellationToken = default)
    {
        await dbContext.Accounts.AddAsync(account, cancellationToken);
        await dbContext.ProvisioningRecords.AddAsync(record, cancellationToken);
        await dbContext.SaveChangesAsync(cancellationToken);
    }

    public async Task UpdateAsync(
        ProvisioningRecord record,
        CancellationToken cancellationToken = default)
    {
        if (dbContext.Entry(record).State == EntityState.Detached)
        {
            dbContext.ProvisioningRecords.Update(record);
        }

        await dbContext.SaveChangesAsync(cancellationToken);
    }

    public async Task UpdateWithAccountAsync(
        ProvisioningRecord record,
        IdentityAccount account,
        CancellationToken cancellationToken = default)
    {
        if (dbContext.Entry(account).State == EntityState.Detached)
        {
            dbContext.Accounts.Update(account);
        }

        if (dbContext.Entry(record).State == EntityState.Detached)
        {
            dbContext.ProvisioningRecords.Update(record);
        }

        await dbContext.SaveChangesAsync(cancellationToken);
    }
}
