using Saas.Identity.Domain.Common;
using Saas.Identity.Domain.Entities;
using Saas.Identity.Domain.ValueObjects;

namespace Saas.Identity.Domain.Policies;

public static class StaffManagementPolicy
{
    public static readonly DomainError ForbiddenAdminClinica = new(
        "FORBIDDEN_ADMIN_CLINICA",
        "Solo un AdminClinica activo de este tenant puede administrar el personal de la clínica.",
        403);

    public static readonly DomainError TenantNotActive = new(
        "TENANT_NOT_ACTIVE",
        "No se puede administrar personal mientras la clínica no esté en estado ACTIVA.",
        403);

    public static readonly DomainError PrivilegeEscalationBlocked = new(
        "PRIVILEGE_ESCALATION_BLOCKED",
        "AdminClinica no puede asignar el rol SuperAdmin ni privilegios superiores a su autoridad (CU-14).",
        403);

    public static readonly DomainError AttributionRequired = new(
        "ATTRIBUTION_REQUIRED",
        "Solo se puede habilitar la emisión de prescripciones a un Especialista con atribución profesional registrada (CU-14).",
        400);

    public static readonly DomainError DuplicateStaffEmail = new(
        "DUPLICATE_STAFF_EMAIL",
        "Ya existe una cuenta registrada con ese correo electrónico dentro de esta clínica.",
        409);

    public static readonly DomainError AccountNotFound = new(
        "ACCOUNT_NOT_FOUND",
        "No se encontró la cuenta solicitada.",
        404);

    public static readonly DomainError TenantIsolation = new(
        "TENANT_ISOLATION",
        "La cuenta seleccionada no pertenece a tu clínica.",
        403);

    public static readonly DomainError LastAdminProtected = new(
        "LAST_ADMIN_PROTECTED",
        "Debe permanecer al menos un AdminClinica activo en la clínica para mantener la administración operativa.",
        409);

    public static readonly DomainError InvalidAuxiliary = new(
        "INVALID_AUXILIARY",
        "La cuenta seleccionada no corresponde a un auxiliar de tu clínica.",
        400);

    public static readonly DomainError InvalidLinkedSpecialist = new(
        "INVALID_LINKED_SPECIALIST",
        "Todos los especialistas vinculados deben ser cuentas Especialista activas dentro de la misma clínica.",
        400);

    public static DomainError QuotaReached(int activeCount, int maxActiveAccounts) =>
        new(
            "QUOTA_REACHED",
            $"Cuota del plan alcanzada ({activeCount}/{maxActiveAccounts} cuentas activas). Solicita ampliación a SuperAdmin (CU-17 A2).",
            409);

    public static Result ValidateActorAndTenant(
        IdentityAccount? actor,
        TenantAccessState? tenant,
        bool platformUnavailable)
    {
        if (actor is null ||
            !actor.Active ||
            actor.Role != OrgRole.ADMIN_CLINICA ||
            actor.TenantId is null)
        {
            return Result.Failure(ForbiddenAdminClinica);
        }

        var tenantCheck = AuthenticationPolicy.ValidateTenantAccess(tenant, platformUnavailable);
        if (tenantCheck.IsFailure)
        {
            return Result.Failure(tenantCheck.Error.HttpStatus == 403
                ? TenantNotActive
                : tenantCheck.Error);
        }

        if (actor.TenantId != tenant!.TenantId)
        {
            return Result.Failure(TenantIsolation);
        }

        return Result.Success();
    }

    public static Result ValidateCreate(
        TenantAccessState tenant,
        int activeCountInTenant,
        OrgRole requestedRole,
        bool hasAttribution,
        bool requestedCanPrescribe)
    {
        if (requestedRole == OrgRole.SUPER_ADMIN)
        {
            return Result.Failure(PrivilegeEscalationBlocked);
        }

        if (activeCountInTenant >= tenant.MaxActiveAccounts)
        {
            return Result.Failure(QuotaReached(activeCountInTenant, tenant.MaxActiveAccounts));
        }

        if (requestedCanPrescribe && (requestedRole != OrgRole.ESPECIALISTA || !hasAttribution))
        {
            return Result.Failure(AttributionRequired);
        }

        return Result.Success();
    }

    public static Result ValidateUpdateRole(
        IdentityAccount actor,
        IdentityAccount? target,
        OrgRole nextRole,
        bool nextCanPrescribe,
        bool hasAttribution,
        int activeAdminsInTenant)
    {
        if (target is null)
        {
            return Result.Failure(AccountNotFound);
        }

        if (target.TenantId != actor.TenantId || target.Role == OrgRole.SUPER_ADMIN)
        {
            return Result.Failure(TenantIsolation);
        }

        if (nextRole == OrgRole.SUPER_ADMIN)
        {
            return Result.Failure(PrivilegeEscalationBlocked);
        }

        if (target.Active &&
            target.Role == OrgRole.ADMIN_CLINICA &&
            nextRole != OrgRole.ADMIN_CLINICA &&
            activeAdminsInTenant <= 1)
        {
            return Result.Failure(LastAdminProtected);
        }

        if (nextCanPrescribe && (nextRole != OrgRole.ESPECIALISTA || !hasAttribution))
        {
            return Result.Failure(AttributionRequired);
        }

        return Result.Success();
    }

    public static Result ValidateStatusChange(
        IdentityAccount actor,
        IdentityAccount? target,
        TenantAccessState tenant,
        int activeCountInTenant,
        int activeAdminsInTenant,
        bool nextActive)
    {
        if (target is null)
        {
            return Result.Failure(AccountNotFound);
        }

        if (target.TenantId != actor.TenantId || target.Role == OrgRole.SUPER_ADMIN)
        {
            return Result.Failure(TenantIsolation);
        }

        if (!nextActive &&
            target.Active &&
            target.Role == OrgRole.ADMIN_CLINICA &&
            activeAdminsInTenant <= 1)
        {
            return Result.Failure(LastAdminProtected);
        }

        if (nextActive &&
            !target.Active &&
            activeCountInTenant >= tenant.MaxActiveAccounts)
        {
            return Result.Failure(QuotaReached(activeCountInTenant, tenant.MaxActiveAccounts));
        }

        return Result.Success();
    }

    public static Result ValidateAuxiliaryLinks(
        IdentityAccount actor,
        IdentityAccount? auxiliary,
        IReadOnlyCollection<Guid> requestedSpecialistIds,
        IReadOnlyCollection<IdentityAccount> tenantAccounts)
    {
        if (auxiliary is null)
        {
            return Result.Failure(AccountNotFound);
        }

        if (auxiliary.TenantId != actor.TenantId)
        {
            return Result.Failure(TenantIsolation);
        }

        if (auxiliary.Role != OrgRole.AUXILIAR)
        {
            return Result.Failure(InvalidAuxiliary);
        }

        var accountLookup = tenantAccounts.ToDictionary(a => a.Id);
        foreach (var specialistId in requestedSpecialistIds.Distinct())
        {
            if (!accountLookup.TryGetValue(specialistId, out var spec) ||
                spec.TenantId != actor.TenantId ||
                spec.Role != OrgRole.ESPECIALISTA ||
                !spec.Active)
            {
                return Result.Failure(InvalidLinkedSpecialist);
            }
        }

        return Result.Success();
    }

    public static StaffPermissions SanitizePermissionsForRole(OrgRole role, StaffPermissions requested) =>
        new(
            CanPrescribe: role == OrgRole.ESPECIALISTA && requested.CanPrescribe,
            CanRegisterPatients: requested.CanRegisterPatients,
            CanAssignInitialPrimary: (role == OrgRole.ADMIN_CLINICA || role == OrgRole.AUXILIAR) && requested.CanAssignInitialPrimary,
            CanUploadStudies: role == OrgRole.AUXILIAR && requested.CanUploadStudies);
}
