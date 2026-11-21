using Saas.Identity.Application.Ports;
using Saas.Identity.Domain.Common;
using Saas.Identity.Domain.Entities;
using Saas.Identity.Domain.Policies;
using Saas.Identity.Domain.ValueObjects;

namespace Saas.Identity.Application.UseCases.Auth;

public sealed class LoginClinicUseCase(
    IAccountRepository accountRepository,
    IRefreshTokenRepository refreshTokenRepository,
    ITenantAccessStatePort tenantAccessStatePort,
    IPasswordHasherPort passwordHasher,
    ITokenIssuerPort tokenIssuer,
    IClockPort clock)
{
    public async Task<Result<AuthSessionResult>> ExecuteAsync(
        LoginClinicCommand command,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(command.ClinicSlug) ||
            string.IsNullOrWhiteSpace(command.Email) ||
            string.IsNullOrWhiteSpace(command.Password))
        {
            return Result.Failure<AuthSessionResult>(SessionAssembler.MissingLoginFields);
        }

        var lookup = await tenantAccessStatePort.GetBySlugAsync(
            command.ClinicSlug.Trim().ToLowerInvariant(),
            cancellationToken);

        var tenantCheck = AuthenticationPolicy.ValidateTenantAccess(
            lookup.Tenant,
            lookup.PlatformUnavailable);
        if (tenantCheck.IsFailure)
        {
            return Result.Failure<AuthSessionResult>(tenantCheck.Error);
        }

        var utcNow = clock.UtcNow;
        var normalizedEmail = IdentityAccount.NormalizeEmail(command.Email);
        var account = await accountRepository.FindByClinicEmailAsync(
            lookup.Tenant!.TenantId,
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

        if (account.Role != OrgRole.SUPER_ADMIN &&
            account.TenantId == lookup.Tenant.TenantId &&
            !passwordMatches)
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

        var policyResult = AuthenticationPolicy.ValidateClinicLogin(
            lookup.Tenant,
            lookup.PlatformUnavailable,
            account,
            passwordMatches);

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
            lookup.Tenant,
            tokenIssuer,
            utcNow);

        await refreshTokenRepository.AddAsync(session, cancellationToken);
        return Result.Success(response);
    }
}
