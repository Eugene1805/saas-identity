using Saas.Identity.Application.Ports;
using Saas.Identity.Domain.Common;

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

        var presentedHash = tokenIssuer.HashRefreshToken(command.RefreshToken.Trim());
        var existingSession = await refreshTokenRepository.FindByTokenHashAsync(
            presentedHash,
            cancellationToken);

        if (existingSession is not null && !existingSession.IsRevoked)
        {
            existingSession.Revoke(clock.UtcNow, "USER_LOGOUT");
            await refreshTokenRepository.UpdateAsync(existingSession, cancellationToken);
        }

        return Result.Success();
    }
}
