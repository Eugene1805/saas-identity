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

        var rawRefreshToken = command.RefreshToken.Trim();
        if (!tokenIssuer.TryResolveRefreshTokenScope(rawRefreshToken, out var storeScope))
        {
            return Result.Failure<AuthSessionResult>(SessionAssembler.InvalidRefreshToken);
        }

        var utcNow = clock.UtcNow;
        var presentedHash = tokenIssuer.HashRefreshToken(rawRefreshToken);

        try
        {
            var existingSession = await refreshTokenRepository.FindByTokenHashAsync(
                storeScope,
                presentedHash,
                cancellationToken);

            if (existingSession is null || existingSession.TenantId != storeScope.TenantId)
            {
                return Result.Failure<AuthSessionResult>(SessionAssembler.InvalidRefreshToken);
            }

            if (existingSession.IsRevoked)
            {
                // Detección de reutilización de refresh token: revocar todas las sesiones activas de la cuenta.
                await refreshTokenRepository.RevokeAllForAccountAsync(
                    storeScope,
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

            var account = await accountRepository.FindByIdAsync(
                storeScope,
                existingSession.AccountId,
                cancellationToken);
            if (account is null || account.TenantId != storeScope.TenantId)
            {
                return Result.Failure<AuthSessionResult>(AuthenticationPolicy.InvalidCredentials);
            }

            if (!account.Active)
            {
                return Result.Failure<AuthSessionResult>(AuthenticationPolicy.AccountDisabled);
            }

            TenantAccessState? tenantState = null;
            if (storeScope.TenantId is Guid tenantId)
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
            await refreshTokenRepository.RotateAsync(storeScope, existingSession, newSession, cancellationToken);

            return Result.Success(response);
        }
        catch (TenantDatabaseUnavailableException)
        {
            return Result.Failure<AuthSessionResult>(AuthenticationPolicy.TenantDatabaseUnavailable);
        }
    }
}
