using Saas.Identity.Application.Ports;
using Saas.Identity.Domain.Common;
using Saas.Identity.Domain.Policies;

namespace Saas.Identity.Application.UseCases.Auth;

public sealed class GetCurrentAccountUseCase(
    IAccountRepository accountRepository,
    ITenantAccessStatePort tenantAccessStatePort)
{
    public async Task<Result<AccountProfileDto>> ExecuteAsync(
        Guid accountId,
        CancellationToken cancellationToken = default)
    {
        var account = await accountRepository.FindByIdAsync(accountId, cancellationToken);
        if (account is null)
        {
            return Result.Failure<AccountProfileDto>(AuthenticationPolicy.InvalidCredentials);
        }

        if (!account.Active)
        {
            return Result.Failure<AccountProfileDto>(AuthenticationPolicy.AccountDisabled);
        }

        if (account.TenantId is Guid tenantId)
        {
            var lookup = await tenantAccessStatePort.GetByTenantIdAsync(tenantId, cancellationToken);
            var tenantCheck = AuthenticationPolicy.ValidateTenantAccess(
                lookup.Tenant,
                lookup.PlatformUnavailable);
            if (tenantCheck.IsFailure)
            {
                return Result.Failure<AccountProfileDto>(tenantCheck.Error);
            }
        }

        return Result.Success(SessionAssembler.ToAccountProfileDto(account));
    }
}
