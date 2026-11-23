using Saas.Identity.Application.Ports;
using Saas.Identity.Domain.Common;
using Saas.Identity.Domain.Policies;

namespace Saas.Identity.Application.UseCases.Auth;

public sealed class ChangePasswordUseCase(
    IAccountRepository accountRepository,
    IPasswordHasherPort passwordHasher)
{
    public async Task<Result> ExecuteAsync(
        ChangePasswordCommand command,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(command.CurrentPassword) ||
            string.IsNullOrWhiteSpace(command.NewPassword))
        {
            return Result.Failure(new DomainError(
                "VALIDATION_ERROR",
                "La contraseña actual y la nueva contraseña son obligatorias.",
                400));
        }

        try
        {
            var account = await accountRepository.FindByIdAsync(
                command.StoreScope,
                command.AccountId,
                cancellationToken);
            if (account is null || account.TenantId != command.StoreScope.TenantId)
            {
                return Result.Failure(AuthenticationPolicy.InvalidCredentials);
            }

            if (!account.Active)
            {
                return Result.Failure(AuthenticationPolicy.AccountDisabled);
            }

            if (!passwordHasher.Verify(account.PasswordHash, command.CurrentPassword))
            {
                return Result.Failure(new DomainError(
                    "INVALID_CREDENTIALS",
                    "La contraseña actual no coincide con tus credenciales vigentes.",
                    401));
            }

            var policyCheck = PasswordPolicy.Validate(command.NewPassword);
            if (policyCheck.IsFailure)
            {
                return policyCheck;
            }

            account.ChangePassword(passwordHasher.Hash(command.NewPassword), mustChangePassword: false);
            await accountRepository.UpdateAsync(command.StoreScope, account, cancellationToken);

            return Result.Success();
        }
        catch (TenantDatabaseUnavailableException)
        {
            return Result.Failure(AuthenticationPolicy.TenantDatabaseUnavailable);
        }
    }
}
