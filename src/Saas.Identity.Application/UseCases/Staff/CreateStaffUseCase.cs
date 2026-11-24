using Saas.Identity.Application.Ports;
using Saas.Identity.Domain.Common;
using Saas.Identity.Domain.Entities;
using Saas.Identity.Domain.Policies;
using Saas.Identity.Domain.ValueObjects;

namespace Saas.Identity.Application.UseCases.Staff;

public sealed class CreateStaffUseCase(
    IAccountRepository accountRepository,
    ITenantAccessStatePort tenantAccessStatePort,
    IPasswordHasherPort passwordHasher,
    ITemporaryPasswordGeneratorPort temporaryPasswordGenerator,
    ITemporaryPasswordDeliveryPort temporaryPasswordDelivery,
    IClockPort clock)
{
    public async Task<Result<CreateStaffResult>> ExecuteAsync(
        CreateStaffCommand command,
        CancellationToken cancellationToken = default)
    {
        try
        {
            var (_, tenant, error) = await StaffAssembler.LoadAuthorizedActorAndTenantAsync(
                accountRepository,
                tenantAccessStatePort,
                command.ActorStoreScope,
                command.ActorAccountId,
                cancellationToken);

            if (error is not null)
            {
                return Result.Failure<CreateStaffResult>(error);
            }

            if (string.IsNullOrWhiteSpace(command.FullName) ||
                string.IsNullOrWhiteSpace(command.Email) ||
                !command.Email.Contains('@'))
            {
                return Result.Failure<CreateStaffResult>(StaffAssembler.MissingRequiredFields);
            }

            if (!StaffAssembler.TryParseOrgRole(command.Role, out var requestedRole))
            {
                return Result.Failure<CreateStaffResult>(StaffAssembler.InvalidRoleValue);
            }

            var hasAttribution = !string.IsNullOrWhiteSpace(command.LicenseCode) &&
                !string.IsNullOrWhiteSpace(command.Title);

            var activeCount = await accountRepository.CountActiveByTenantAsync(tenant!.TenantId, cancellationToken);
            var policyCheck = StaffManagementPolicy.ValidateCreate(
                tenant,
                activeCount,
                requestedRole,
                hasAttribution,
                command.Permissions.CanPrescribe);

            if (policyCheck.IsFailure)
            {
                return Result.Failure<CreateStaffResult>(policyCheck.Error);
            }

            var normalizedEmail = IdentityAccount.NormalizeEmail(command.Email);
            var existing = await accountRepository.FindByClinicEmailAsync(
                tenant.TenantId,
                normalizedEmail,
                cancellationToken);

            if (existing is not null)
            {
                return Result.Failure<CreateStaffResult>(StaffManagementPolicy.DuplicateStaffEmail);
            }

            string rawPassword;
            bool mustChangePassword;
            string? temporaryPassword;

            if (command.GenerateTemporaryPassword || string.IsNullOrWhiteSpace(command.Password))
            {
                rawPassword = temporaryPasswordGenerator.Generate();
                mustChangePassword = true;
                temporaryPassword = rawPassword;
            }
            else
            {
                var passwordCheck = PasswordPolicy.Validate(command.Password);
                if (passwordCheck.IsFailure)
                {
                    return Result.Failure<CreateStaffResult>(passwordCheck.Error);
                }

                rawPassword = command.Password;
                mustChangePassword = false;
                temporaryPassword = null;
            }

            var utcNow = clock.UtcNow;
            var attribution = requestedRole == OrgRole.ESPECIALISTA && hasAttribution
                ? new ProfessionalAttribution(
                    command.LicenseCode!.Trim(),
                    command.Title!.Trim(),
                    Gmt6Clock.FormatIsoGmt6(utcNow))
                : null;

            var specialty = requestedRole == OrgRole.ESPECIALISTA
                ? (string.IsNullOrWhiteSpace(command.Specialty) ? "Medicina General" : command.Specialty.Trim())
                : null;

            var sanitizedPermissions = StaffManagementPolicy.SanitizePermissionsForRole(
                requestedRole,
                command.Permissions);

            var account = IdentityAccount.Create(
                Guid.NewGuid(),
                tenant.TenantId,
                command.FullName,
                command.Email,
                passwordHasher.Hash(rawPassword),
                requestedRole,
                active: true,
                specialty,
                attribution,
                sanitizedPermissions,
                linkedSpecialistIds: null,
                utcNow,
                mustChangePassword);

            await accountRepository.AddAsync(command.ActorStoreScope, account, cancellationToken);

            var emailSent = false;
            if (temporaryPassword is not null)
            {
                var delivery = await temporaryPasswordDelivery.SendTemporaryPasswordAsync(
                    new TemporaryPasswordEmailMessage(
                        account.Email,
                        account.FullName,
                        tenant.Slug,
                        tenant.Name,
                        temporaryPassword,
                        IsInitialClinicAdmin: false),
                    cancellationToken);
                emailSent = delivery.Succeeded;
            }

            return Result.Success(new CreateStaffResult(
                StaffAssembler.ToStaffMemberDto(account, []),
                temporaryPassword,
                emailSent));
        }
        catch (TenantDatabaseUnavailableException)
        {
            return Result.Failure<CreateStaffResult>(AuthenticationPolicy.TenantDatabaseUnavailable);
        }
    }
}
