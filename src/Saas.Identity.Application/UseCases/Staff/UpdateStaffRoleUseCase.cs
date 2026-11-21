using Saas.Identity.Application.Ports;
using Saas.Identity.Domain.Common;
using Saas.Identity.Domain.Entities;
using Saas.Identity.Domain.Policies;
using Saas.Identity.Domain.ValueObjects;

namespace Saas.Identity.Application.UseCases.Staff;

public sealed class UpdateStaffRoleUseCase(
    IAccountRepository accountRepository,
    ITenantAccessStatePort tenantAccessStatePort,
    IClockPort clock)
{
    public async Task<Result<StaffMemberDto>> ExecuteAsync(
        UpdateStaffRoleCommand command,
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

        if (!StaffAssembler.TryParseOrgRole(command.Role, out var nextRole))
        {
            return Result.Failure<StaffMemberDto>(StaffAssembler.InvalidRoleValue);
        }

        var target = await accountRepository.FindByIdAsync(command.TargetAccountId, cancellationToken);
        var hasNewAttribution = !string.IsNullOrWhiteSpace(command.LicenseCode) &&
            !string.IsNullOrWhiteSpace(command.Title);
        var hasAttribution = hasNewAttribution || target?.ProfessionalAttribution is not null;
        var activeAdmins = await accountRepository.CountActiveAdminsByTenantAsync(tenant!.TenantId, cancellationToken);

        var check = StaffManagementPolicy.ValidateUpdateRole(
            actor!,
            target,
            nextRole,
            command.CanPrescribe,
            hasAttribution,
            activeAdmins);

        if (check.IsFailure)
        {
            return Result.Failure<StaffMemberDto>(check.Error);
        }

        var utcNow = clock.UtcNow;
        var previousRole = target!.Role;
        var previousCanPrescribe = target.Permissions.CanPrescribe;

        var nextAttribution = nextRole == OrgRole.ESPECIALISTA
            ? (hasNewAttribution
                ? new ProfessionalAttribution(
                    command.LicenseCode!.Trim(),
                    command.Title!.Trim(),
                    target.ProfessionalAttribution?.RegisteredAtGmt6 ?? Gmt6Clock.FormatIsoGmt6(utcNow))
                : target.ProfessionalAttribution)
            : null;

        var nextSpecialty = nextRole == OrgRole.ESPECIALISTA
            ? (!string.IsNullOrWhiteSpace(command.Specialty) ? command.Specialty : target.Specialty)
            : null;

        var sanitizedPermissions = StaffManagementPolicy.SanitizePermissionsForRole(
            nextRole,
            new StaffPermissions(
                command.CanPrescribe,
                command.CanRegisterPatients,
                command.CanAssignInitialPrimary,
                command.CanUploadStudies));

        target.UpdateRoleAndPermissions(nextRole, nextSpecialty, nextAttribution, sanitizedPermissions);

        var auditEntry = RoleAuditEntry.Create(
            Guid.NewGuid(),
            tenant.TenantId,
            target.Id,
            previousRole,
            nextRole,
            previousCanPrescribe,
            sanitizedPermissions.CanPrescribe,
            actor!.Id,
            actor.FullName,
            utcNow,
            command.Note ?? string.Empty);

        await accountRepository.UpdateWithRoleAuditAsync(target, auditEntry, cancellationToken);
        var auditHistory = await accountRepository.ListRoleAuditForAccountAsync(target.Id, cancellationToken);

        return Result.Success(StaffAssembler.ToStaffMemberDto(target, auditHistory));
    }
}
