using Saas.Identity.Domain.Common;
using Saas.Identity.Domain.Entities;
using Saas.Identity.Domain.ValueObjects;

namespace Saas.Identity.Domain.Policies;

public static class AuthenticationPolicy
{
    public static readonly DomainError InvalidCredentials = new(
        "INVALID_CREDENTIALS",
        "Credenciales inválidas para el contexto seleccionado.",
        401);

    public static readonly DomainError TenantStateUnavailable = new(
        "TENANT_STATE_UNAVAILABLE",
        "No fue posible verificar de forma confiable el estado operativo de la clínica.",
        503);

    public static readonly DomainError TenantNotFound = new(
        "TENANT_NOT_FOUND",
        "No se encontró una clínica con ese identificador.",
        404);

    public static readonly DomainError TenantPendingAdmin = new(
        "TENANT_PENDING_ADMIN",
        "La clínica está en estado PENDIENTE_ADMIN hasta completar la habilitación de su administrador inicial.",
        403);

    public static readonly DomainError TenantSuspended = new(
        "TENANT_SUSPENDED",
        "La clínica se encuentra SUSPENDIDA. Los datos permanecen conservados sin permitir acceso ordinario.",
        403);

    public static readonly DomainError AccountDisabled = new(
        "ACCOUNT_DISABLED",
        "Tu cuenta se encuentra desactivada por AdminClinica. Contacta al administrador de tu sede.",
        403);

    public static readonly DomainError RefreshTokenRevoked = new(
        "REFRESH_TOKEN_REVOKED",
        "La sesión fue revocada o se detectó reutilización de refresh token.",
        401);

    public static readonly DomainError RefreshTokenExpired = new(
        "REFRESH_TOKEN_EXPIRED",
        "El refresh token ha expirado; inicia sesión nuevamente.",
        401);

    public static readonly DomainError TenantDatabaseUnavailable = new(
        "TENANT_DATABASE_UNAVAILABLE",
        "No fue posible acceder a la base de datos privada de identidad de la clínica.",
        503);

    public static Result ValidateClinicLogin(
        TenantAccessState? tenant,
        bool platformUnavailable,
        IdentityAccount? account,
        bool passwordMatches)
    {
        var tenantCheck = ValidateTenantAccess(tenant, platformUnavailable);
        if (tenantCheck.IsFailure)
        {
            return tenantCheck;
        }

        if (account is null ||
            account.Role == OrgRole.SUPER_ADMIN ||
            account.TenantId != tenant!.TenantId ||
            !passwordMatches)
        {
            return Result.Failure(InvalidCredentials);
        }

        if (!account.Active)
        {
            return Result.Failure(AccountDisabled);
        }

        return Result.Success();
    }

    public static Result ValidatePlatformLogin(
        IdentityAccount? account,
        bool passwordMatches)
    {
        if (account is null ||
            account.Role != OrgRole.SUPER_ADMIN ||
            account.TenantId is not null ||
            !passwordMatches)
        {
            return Result.Failure(InvalidCredentials);
        }

        if (!account.Active)
        {
            return Result.Failure(AccountDisabled);
        }

        return Result.Success();
    }

    public static Result ValidateTenantAccess(TenantAccessState? tenant, bool platformUnavailable)
    {
        if (platformUnavailable)
        {
            return Result.Failure(TenantStateUnavailable);
        }

        if (tenant is null)
        {
            return Result.Failure(TenantNotFound);
        }

        if (tenant.State == TenantOperationalState.PENDIENTE_ADMIN)
        {
            return Result.Failure(TenantPendingAdmin);
        }

        if (tenant.State == TenantOperationalState.SUSPENDIDA || !tenant.MayAuthenticate)
        {
            return Result.Failure(TenantSuspended);
        }

        return Result.Success();
    }
}
