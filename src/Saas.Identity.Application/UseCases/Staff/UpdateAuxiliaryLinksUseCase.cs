using Saas.Identity.Application.Ports;
using Saas.Identity.Domain.Common;
using Saas.Identity.Domain.Policies;

namespace Saas.Identity.Application.UseCases.Staff;

public sealed class UpdateAuxiliaryLinksUseCase(
    IAccountRepository accountRepository,
    ITenantAccessStatePort tenantAccessStatePort)
{
    public async Task<Result<StaffMemberDto>> ExecuteAsync(
        UpdateAuxiliaryLinksCommand command,
        CancellationToken cancellationToken = default)
    {
        try
        {
            var (actor, tenant, error) = await StaffAssembler.LoadAuthorizedActorAndTenantAsync(
                accountRepository,
                tenantAccessStatePort,
                command.ActorStoreScope,
                command.ActorAccountId,
                cancellationToken);

            if (error is not null)
            {
                return Result.Failure<StaffMemberDto>(error);
            }

            var target = await accountRepository.FindByIdAsync(
                command.ActorStoreScope,
                command.TargetAccountId,
                cancellationToken);
            var tenantAccounts = await accountRepository.ListByTenantAsync(tenant!.TenantId, cancellationToken);

            var check = StaffManagementPolicy.ValidateAuxiliaryLinks(
                actor!,
                target,
                command.SpecialistIds,
                tenantAccounts);

            if (check.IsFailure)
            {
                return Result.Failure<StaffMemberDto>(check.Error);
            }

            target!.UpdateLinkedSpecialists(command.SpecialistIds);
            await accountRepository.UpdateAsync(command.ActorStoreScope, target, cancellationToken);

            var auditHistory = await accountRepository.ListRoleAuditForAccountAsync(
                tenant.TenantId,
                target.Id,
                cancellationToken);
            return Result.Success(StaffAssembler.ToStaffMemberDto(target, auditHistory));
        }
        catch (TenantDatabaseUnavailableException)
        {
            return Result.Failure<StaffMemberDto>(AuthenticationPolicy.TenantDatabaseUnavailable);
        }
    }
}
