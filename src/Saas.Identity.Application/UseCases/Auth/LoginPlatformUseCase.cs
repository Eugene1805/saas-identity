using Saas.Identity.Application.Ports;
using Saas.Identity.Domain.Common;
using Saas.Identity.Domain.Entities;
using Saas.Identity.Domain.Policies;
using Saas.Identity.Domain.ValueObjects;

namespace Saas.Identity.Application.UseCases.Auth;

public sealed class LoginPlatformUseCase(
    IAccountRepository accountRepository,
    IRefreshTokenRepository refreshTokenRepository,
    IPasswordHasherPort passwordHasher,
    ITokenIssuerPort tokenIssuer,
    IClockPort clock)
{
    public async Task<Result<AuthSessionResult>> ExecuteAsync(
        LoginPlatformCommand command,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(command.Email) ||
            string.IsNullOrWhiteSpace(command.Password))
        {
            return Result.Failure<AuthSessionResult>(new DomainError(
                "VALIDATION_ERROR",
                "Correo electrónico y contraseña de plataforma son obligatorios.",
                400));
        }

        var utcNow = clock.UtcNow;
        var normalizedEmail = IdentityAccount.NormalizeEmail(command.Email);
        var account = await accountRepository.FindPlatformByEmailAsync(
            normalizedEmail,
            cancellationToken);

        if (account is null)
        {
            return Result.Failure<AuthSessionResult>(AuthenticationPolicy.InvalidCredentials);
        }

        if (account.Active && account.IsLockedOut(utcNow))
        {
            return Result.Failure<AuthSessionResult>(
                LockoutPolicy.CreateLockedOutError(account.LockoutUntilUtc!.Value, utcNow));
        }

        var passwordMatches = passwordHasher.Verify(account.PasswordHash, command.Password);
        if (account.Role == OrgRole.SUPER_ADMIN && account.TenantId is null && !passwordMatches)
        {
            if (account.Active)
            {
                account.RecordFailedLogin(utcNow);
                await accountRepository.UpdateAsync(account, cancellationToken);

                if (account.IsLockedOut(utcNow))
                {
                    return Result.Failure<AuthSessionResult>(
                        LockoutPolicy.CreateLockedOutError(account.LockoutUntilUtc!.Value, utcNow));
                }
            }

            return Result.Failure<AuthSessionResult>(AuthenticationPolicy.InvalidCredentials);
        }

        var policyResult = AuthenticationPolicy.ValidatePlatformLogin(account, passwordMatches);
        if (policyResult.IsFailure)
        {
            return Result.Failure<AuthSessionResult>(policyResult.Error);
        }

        if (account.FailedLoginAttempts > 0 || account.LockoutUntilUtc is not null)
        {
            account.ResetLoginFailures();
            await accountRepository.UpdateAsync(account, cancellationToken);
        }

        var (session, _, response) = SessionAssembler.CreateSessionPair(
            account,
            null,
            tokenIssuer,
            utcNow);

        await refreshTokenRepository.AddAsync(session, cancellationToken);
        return Result.Success(response);
    }
}
