using Saas.Identity.Application.Ports;
using Saas.Identity.Domain.Common;
using Saas.Identity.Domain.Policies;

namespace Saas.Identity.Application.UseCases.Auth;

public sealed class LogoutUseCase(
    IRefreshTokenRepository refreshTokenRepository,
    ITokenIssuerPort tokenIssuer,
    IClockPort clock)
{
    public async Task<Result> ExecuteAsync(
        LogoutCommand command,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(command.RefreshToken))
        {
            return Result.Failure(SessionAssembler.MissingRefreshToken);
        }

        var rawRefreshToken = command.RefreshToken.Trim();
        if (!tokenIssuer.TryResolveRefreshTokenScope(rawRefreshToken, out var storeScope))
        {
            return Result.Success();
        }

        var presentedHash = tokenIssuer.HashRefreshToken(rawRefreshToken);

        try
        {
            var existingSession = await refreshTokenRepository.FindByTokenHashAsync(
                storeScope,
                presentedHash,
                cancellationToken);

            if (existingSession is not null &&
                existingSession.TenantId == storeScope.TenantId &&
                !existingSession.IsRevoked)
            {
                existingSession.Revoke(clock.UtcNow, "USER_LOGOUT");
                await refreshTokenRepository.UpdateAsync(storeScope, existingSession, cancellationToken);
            }

            return Result.Success();
        }
        catch (TenantDatabaseUnavailableException)
        {
            return Result.Failure(AuthenticationPolicy.TenantDatabaseUnavailable);
        }
    }
}
