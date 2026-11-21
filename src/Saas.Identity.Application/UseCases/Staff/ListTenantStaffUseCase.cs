using Saas.Identity.Application.Ports;
using Saas.Identity.Domain.Common;

namespace Saas.Identity.Application.UseCases.Staff;

public sealed class ListTenantStaffUseCase(
    IAccountRepository accountRepository,
    ITenantAccessStatePort tenantAccessStatePort)
{
    public async Task<Result<TenantStaffDirectoryResult>> ExecuteAsync(
        Guid actorAccountId,
        CancellationToken cancellationToken = default)
    {
        var (_, tenant, error) = await StaffAssembler.LoadAuthorizedActorAndTenantAsync(
            accountRepository,
            tenantAccessStatePort,
            actorAccountId,
            cancellationToken);

        if (error is not null)
        {
            return Result.Failure<TenantStaffDirectoryResult>(error);
        }

        var accounts = await accountRepository.ListByTenantAsync(tenant!.TenantId, cancellationToken);
        var auditByAccount = await accountRepository.ListRoleAuditByTenantAsync(tenant.TenantId, cancellationToken);

        var dtos = accounts
            .Select(account => StaffAssembler.ToStaffMemberDto(
                account,
                auditByAccount.TryGetValue(account.Id, out var entries) ? entries : []))
            .ToList();

        var activeCount = accounts.Count(a => a.Active);

        return Result.Success(new TenantStaffDirectoryResult(
            tenant.TenantId,
            tenant.Slug,
            tenant.Name,
            activeCount,
            tenant.MaxActiveAccounts,
            dtos));
    }
}
