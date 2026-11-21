using Saas.Identity.Application.Ports;
using Saas.Identity.Domain.Common;
using Saas.Identity.Domain.Policies;
using Saas.Identity.Domain.ValueObjects;

namespace Saas.Identity.Application.UseCases.Auth;

public sealed class RefreshSessionUseCase(
    IAccountRepository accountRepository,
    IRefreshTokenRepository refreshTokenRepository,
    ITenantAccessStatePort tenantAccessStatePort,
    ITokenIssuerPort tokenIssuer,
    IClockPort clock)
{
    public async Task<Result<AuthSessionResult>> ExecuteAsync(
        RefreshSessionCommand command,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(command.RefreshToken))
        {
            return Result.Failure<AuthSessionResult>(SessionAssembler.MissingRefreshToken);
        }

        var utcNow = clock.UtcNow;
        var presentedHash = tokenIssuer.HashRefreshToken(command.RefreshToken.Trim());
        var existingSession = await refreshTokenRepository.FindByTokenHashAsync(
            presentedHash,
            cancellationToken);

        if (existingSession is null)
        {
            return Result.Failure<AuthSessionResult>(SessionAssembler.InvalidRefreshToken);
        }

        if (existingSession.IsRevoked)
        {
            // Detección de reutilización de refresh token: revocar todas las sesiones activas de la cuenta.
            await refreshTokenRepository.RevokeAllForAccountAsync(
                existingSession.AccountId,
                utcNow,
                "REUSE_DETECTED",
                cancellationToken);

            return Result.Failure<AuthSessionResult>(AuthenticationPolicy.RefreshTokenRevoked);
        }

        if (existingSession.IsExpired(utcNow))
        {
            return Result.Failure<AuthSessionResult>(AuthenticationPolicy.RefreshTokenExpired);
        }

        var account = await accountRepository.FindByIdAsync(existingSession.AccountId, cancellationToken);
        if (account is null)
        {
            return Result.Failure<AuthSessionResult>(AuthenticationPolicy.InvalidCredentials);
        }

        if (!account.Active)
        {
            return Result.Failure<AuthSessionResult>(AuthenticationPolicy.AccountDisabled);
        }

        TenantAccessState? tenantState = null;
        if (account.TenantId is Guid tenantId)
        {
            var lookup = await tenantAccessStatePort.GetByTenantIdAsync(tenantId, cancellationToken);
            var tenantCheck = AuthenticationPolicy.ValidateTenantAccess(
                lookup.Tenant,
                lookup.PlatformUnavailable);
            if (tenantCheck.IsFailure)
            {
                return Result.Failure<AuthSessionResult>(tenantCheck.Error);
            }

            tenantState = lookup.Tenant;
        }

        var (newSession, _, response) = SessionAssembler.CreateSessionPair(
            account,
            tenantState,
            tokenIssuer,
            utcNow);

        existingSession.Revoke(utcNow, "ROTATED", newSession.Id);
        await refreshTokenRepository.RotateAsync(existingSession, newSession, cancellationToken);

        return Result.Success(response);
    }
}
