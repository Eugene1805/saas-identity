using Saas.Identity.Application.Ports;
using Saas.Identity.Domain.Common;
using Saas.Identity.Domain.Entities;
using Saas.Identity.Domain.ValueObjects;

namespace Saas.Identity.Application.UseCases.Auth;

public sealed record LoginClinicCommand(
    string ClinicSlug,
    string Email,
    string Password);

public sealed record LoginPlatformCommand(
    string Email,
    string Password);

public sealed record RefreshSessionCommand(
    string RefreshToken);

public sealed record LogoutCommand(
    string RefreshToken);

public sealed record ChangePasswordCommand(
    IdentityStoreScope StoreScope,
    Guid AccountId,
    string CurrentPassword,
    string NewPassword);

public sealed record AccountProfileDto(
    Guid Id,
    Guid? TenantId,
    string FullName,
    string Email,
    string Role,
    bool Active,
    bool MustChangePassword,
    string? Specialty,
    ProfessionalAttribution? ProfessionalAttribution,
    StaffPermissions Permissions,
    IReadOnlyList<Guid> LinkedSpecialistIds,
    string CreatedAtGmt6);

public sealed record AuthTenantSummaryDto(
    Guid TenantId,
    string Slug,
    string Name,
    string State);

public sealed record AuthSessionResult(
    string AccessToken,
    string TokenType,
    string AccessTokenExpiresAtGmt6,
    string RefreshToken,
    string RefreshTokenExpiresAtGmt6,
    AccountProfileDto Account,
    AuthTenantSummaryDto? Tenant);

internal static class SessionAssembler
{
    public static readonly DomainError MissingLoginFields = new(
        "VALIDATION_ERROR",
        "Clínica, correo electrónico y contraseña deben tener un formato válido.",
        400);

    public static readonly DomainError MissingRefreshToken = new(
        "INVALID_REFRESH_TOKEN",
        "El refresh token es obligatorio.",
        400);

    public static readonly DomainError InvalidRefreshToken = new(
        "INVALID_REFRESH_TOKEN",
        "El refresh token proporcionado no es válido.",
        401);

    public static AccountProfileDto ToAccountProfileDto(IdentityAccount account) =>
        new(
            account.Id,
            account.TenantId,
            account.FullName,
            account.Email,
            account.Role.ToString(),
            account.Active,
            account.MustChangePassword,
            account.Specialty,
            account.ProfessionalAttribution,
            account.Permissions,
            account.LinkedSpecialistIds,
            Gmt6Clock.FormatIsoGmt6(account.CreatedAtUtc));

    public static (RefreshTokenSession Session, string RawRefreshToken, AuthSessionResult Response) CreateSessionPair(
        IdentityAccount account,
        TenantAccessState? tenant,
        ITokenIssuerPort tokenIssuer,
        DateTimeOffset utcNow)
    {
        var issuedAccess = tokenIssuer.IssueAccessToken(account, utcNow);
        var rawRefreshToken = tokenIssuer.GenerateRefreshToken(account.TenantId);
        var refreshHash = tokenIssuer.HashRefreshToken(rawRefreshToken);
        var refreshExpiresAtUtc = utcNow.AddDays(tokenIssuer.RefreshTokenLifetimeDays);

        var session = RefreshTokenSession.Create(
            Guid.NewGuid(),
            account.Id,
            account.TenantId,
            refreshHash,
            refreshExpiresAtUtc,
            utcNow);

        var tenantDto = tenant is null
            ? null
            : new AuthTenantSummaryDto(
                tenant.TenantId,
                tenant.Slug,
                tenant.Name,
                tenant.State.ToString());

        var response = new AuthSessionResult(
            issuedAccess.Token,
            "Bearer",
            Gmt6Clock.FormatIsoGmt6(issuedAccess.ExpiresAtUtc),
            rawRefreshToken,
            Gmt6Clock.FormatIsoGmt6(refreshExpiresAtUtc),
            ToAccountProfileDto(account),
            tenantDto);

        return (session, rawRefreshToken, response);
    }
}
