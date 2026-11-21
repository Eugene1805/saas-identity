using Saas.Identity.Application.Ports;
using Saas.Identity.Domain.Common;

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
        var (actor, tenant, error) = await StaffAssembler.LoadAuthorizedActorAndTenantAsync(
            accountRepository,
            tenantAccessStatePort,
            command.ActorAccountId,
            cancellationToken);

        if (error is not null)
        {
            return Result.Failure<StaffMemberDto>(error);
        }

        var target = await accountRepository.FindByIdAsync(command.TargetAccountId, cancellationToken);
        var activeCount = await accountRepository.CountActiveByTenantAsync(tenant!.TenantId, cancellationToken);
        var activeAdmins = await accountRepository.CountActiveAdminsByTenantAsync(tenant.TenantId, cancellationToken);

        var check = Domain.Policies.StaffManagementPolicy.ValidateStatusChange(
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
            await accountRepository.UpdateAsync(target, cancellationToken);

            if (!command.Active)
            {
                await refreshTokenRepository.RevokeAllForAccountAsync(
                    target.Id,
                    clock.UtcNow,
                    "ACCOUNT_DISABLED",
                    cancellationToken);
            }
        }

        var auditHistory = await accountRepository.ListRoleAuditForAccountAsync(target.Id, cancellationToken);
        return Result.Success(StaffAssembler.ToStaffMemberDto(target, auditHistory));
    }
}
