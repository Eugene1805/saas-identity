using Saas.Identity.Application.Ports;
using Saas.Identity.Domain.Common;
using Saas.Identity.Domain.Policies;

namespace Saas.Identity.Application.UseCases.Staff;

public sealed class UpdateStaffStatusUseCase(
    IAccountRepository accountRepository,
    IRefreshTokenRepository refreshTokenRepository,
    ITenantAccessStatePort tenantAccessStatePort,
    IClockPort clock)
{
    public async Task<Result<StaffMemberDto>> ExecuteAsync(
        UpdateStaffStatusCommand command,
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
            var activeCount = await accountRepository.CountActiveByTenantAsync(tenant!.TenantId, cancellationToken);
            var activeAdmins = await accountRepository.CountActiveAdminsByTenantAsync(tenant.TenantId, cancellationToken);

            var check = StaffManagementPolicy.ValidateStatusChange(
                actor!,
                target,
                tenant,
                activeCount,
                activeAdmins,
                command.Active);

            if (check.IsFailure)
            {
                return Result.Failure<StaffMemberDto>(check.Error);
            }

            if (target!.Active != command.Active)
            {
                target.SetActive(command.Active);
                await accountRepository.UpdateAsync(command.ActorStoreScope, target, cancellationToken);

                if (!command.Active)
                {
                    await refreshTokenRepository.RevokeAllForAccountAsync(
                        command.ActorStoreScope,
                        target.Id,
                        clock.UtcNow,
                        "ACCOUNT_DISABLED",
                        cancellationToken);
                }
            }

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
