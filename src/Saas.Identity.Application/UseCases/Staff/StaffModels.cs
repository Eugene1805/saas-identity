using Saas.Identity.Application.Ports;
using Saas.Identity.Domain.Common;
using Saas.Identity.Domain.Entities;
using Saas.Identity.Domain.Policies;
using Saas.Identity.Domain.ValueObjects;

namespace Saas.Identity.Application.UseCases.Staff;

public sealed record RoleAuditEntryDto(
    Guid Id,
    string PreviousRole,
    string NextRole,
    bool PreviousCanPrescribe,
    bool NextCanPrescribe,
    string ActorName,
    string OccurredAtGmt6,
    string Note);

public sealed record StaffMemberDto(
    Guid Id,
    Guid TenantId,
    string FullName,
    string Email,
    string Role,
    bool Active,
    bool MustChangePassword,
    string? Specialty,
    ProfessionalAttribution? ProfessionalAttribution,
    StaffPermissions Permissions,
    IReadOnlyList<Guid> LinkedSpecialistIds,
    string CreatedAtGmt6,
    IReadOnlyList<RoleAuditEntryDto> RoleAuditLog);

public sealed record TenantStaffDirectoryResult(
    Guid TenantId,
    string TenantSlug,
    string TenantName,
    int ActiveCount,
    int MaxActiveAccounts,
    IReadOnlyList<StaffMemberDto> Accounts);

public sealed record CreateStaffCommand(
    Guid ActorAccountId,
    string FullName,
    string Email,
    string? Password,
    bool GenerateTemporaryPassword,
    string Role,
    string? Specialty,
    string? LicenseCode,
    string? Title,
    StaffPermissions Permissions);

public sealed record CreateStaffResult(
    StaffMemberDto Account,
    string? TemporaryPassword,
    bool TemporaryPasswordEmailSent = false);

public sealed record UpdateStaffRoleCommand(
    Guid ActorAccountId,
    Guid TargetAccountId,
    string Role,
    string? Specialty,
    string? LicenseCode,
    string? Title,
    bool CanPrescribe,
    bool CanRegisterPatients,
    bool CanAssignInitialPrimary,
    bool CanUploadStudies,
    string? Note);

public sealed record UpdateStaffStatusCommand(
    Guid ActorAccountId,
    Guid TargetAccountId,
    bool Active);

public sealed record UpdateAuxiliaryLinksCommand(
    Guid ActorAccountId,
    Guid TargetAccountId,
    IReadOnlyList<Guid> SpecialistIds);

internal static class StaffAssembler
{
    public static readonly DomainError MissingRequiredFields = new(
        "VALIDATION_ERROR",
        "Nombre completo y correo institucional válido son obligatorios.",
        400);

    public static readonly DomainError InvalidRoleValue = new(
        "VALIDATION_ERROR",
        "El rol indicado no pertenece al catálogo organizacional permitido.",
        400);

    public static async Task<(IdentityAccount? Actor, TenantAccessState? Tenant, DomainError? Error)>
        LoadAuthorizedActorAndTenantAsync(
            IAccountRepository accountRepository,
            ITenantAccessStatePort tenantAccessStatePort,
            Guid actorAccountId,
            CancellationToken cancellationToken)
    {
        var actor = await accountRepository.FindByIdAsync(actorAccountId, cancellationToken);
        if (actor is null || !actor.Active || actor.Role != OrgRole.ADMIN_CLINICA || actor.TenantId is not Guid tenantId)
        {
            return (null, null, StaffManagementPolicy.ForbiddenAdminClinica);
        }

        var lookup = await tenantAccessStatePort.GetByTenantIdAsync(tenantId, cancellationToken);
        var check = StaffManagementPolicy.ValidateActorAndTenant(
            actor,
            lookup.Tenant,
            lookup.PlatformUnavailable);

        return check.IsFailure
            ? (null, null, check.Error)
            : (actor, lookup.Tenant, null);
    }

    public static bool TryParseOrgRole(string? roleText, out OrgRole role)
    {
        if (string.IsNullOrWhiteSpace(roleText))
        {
            role = default;
            return false;
        }

        return Enum.TryParse(roleText.Trim(), ignoreCase: true, out role) && Enum.IsDefined(role);
    }

    public static RoleAuditEntryDto ToAuditDto(RoleAuditEntry entry) =>
        new(
            entry.Id,
            entry.PreviousRole.ToString(),
            entry.NextRole.ToString(),
            entry.PreviousCanPrescribe,
            entry.NextCanPrescribe,
            entry.ActorName,
            Gmt6Clock.FormatIsoGmt6(entry.OccurredAtUtc),
            entry.Note);

    public static StaffMemberDto ToStaffMemberDto(
        IdentityAccount account,
        IReadOnlyList<RoleAuditEntry> auditEntries) =>
        new(
            account.Id,
            account.TenantId!.Value,
            account.FullName,
            account.Email,
            account.Role.ToString(),
            account.Active,
            account.MustChangePassword,
            account.Specialty,
            account.ProfessionalAttribution,
            account.Permissions,
            account.LinkedSpecialistIds,
            Gmt6Clock.FormatIsoGmt6(account.CreatedAtUtc),
            auditEntries.Select(ToAuditDto).ToList());
}
