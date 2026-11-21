using Saas.Identity.Application.Ports;
using Saas.Identity.Domain.Common;
using Saas.Identity.Domain.Entities;
using Saas.Identity.Domain.Policies;
using Saas.Identity.Domain.ValueObjects;

namespace Saas.Identity.Application.UseCases.Provisioning;

public sealed class ProvisionInitialClinicAdminUseCase(
    IProvisioningRecordRepository provisioningRepository,
    IAccountRepository accountRepository,
    IPasswordHasherPort passwordHasher,
    ITemporaryPasswordGeneratorPort temporaryPasswordGenerator,
    ITemporaryPasswordDeliveryPort temporaryPasswordDelivery,
    IClockPort clock)
{
    public static readonly DomainError InvalidRequest = new(
        "VALIDATION_ERROR",
        "tenantId, provisioningRequestId, adminFullName y adminEmail válido son obligatorios.",
        400);

    public static readonly DomainError ProvisioningConflict = new(
        "PROVISIONING_CONFLICT",
        "El provisioningRequestId ya fue utilizado con datos distintos de clínica o administrador.",
        409);

    public static readonly DomainError InitialAdminAlreadyExists = new(
        "INITIAL_ADMIN_ALREADY_EXISTS",
        "La clínica ya cuenta con un AdminClinica activo habilitado en Identity.",
        409);

    public static readonly DomainError EmailDeliveryFailed = new(
        "EMAIL_DELIVERY_FAILED",
        "No fue posible enviar por correo la contraseña temporal del administrador inicial. Reintenta con el mismo provisioningRequestId.",
        503);

    public async Task<Result<ProvisionInitialClinicAdminResult>> ExecuteAsync(
        ProvisionInitialClinicAdminCommand command,
        CancellationToken cancellationToken = default)
    {
        if (command.TenantId == Guid.Empty ||
            string.IsNullOrWhiteSpace(command.ProvisioningRequestId) ||
            string.IsNullOrWhiteSpace(command.AdminFullName) ||
            string.IsNullOrWhiteSpace(command.AdminEmail) ||
            !command.AdminEmail.Contains('@'))
        {
            return Result.Failure<ProvisionInitialClinicAdminResult>(InvalidRequest);
        }

        var utcNow = clock.UtcNow;
        var cleanRequestId = command.ProvisioningRequestId.Trim();
        var normalizedEmail = IdentityAccount.NormalizeEmail(command.AdminEmail);
        var slug = string.IsNullOrWhiteSpace(command.ClinicSlug)
            ? command.TenantId.ToString("N")[..12]
            : command.ClinicSlug.Trim().ToLowerInvariant();
        var clinicName = string.IsNullOrWhiteSpace(command.ClinicName)
            ? slug
            : command.ClinicName.Trim();

        var existingRecord = await provisioningRepository.FindByRequestIdAsync(
            cleanRequestId,
            cancellationToken);

        if (existingRecord is not null)
        {
            if (!existingRecord.MatchesPayload(command.TenantId, normalizedEmail, command.AdminFullName))
            {
                return Result.Failure<ProvisionInitialClinicAdminResult>(ProvisioningConflict);
            }

            if (existingRecord.Status == ProvisioningRecordStatus.READY &&
                existingRecord.InitialAdminAccountId is Guid readyAccountId)
            {
                return Result.Success(new ProvisionInitialClinicAdminResult(
                    existingRecord.TenantId,
                    existingRecord.ProvisioningRequestId,
                    readyAccountId,
                    ProvisioningRecordStatus.READY,
                    Gmt6Clock.FormatIsoGmt6(utcNow),
                    existingRecord.TemporaryPasswordEmailSent));
            }

            return await RetryExistingProvisioningAsync(
                existingRecord,
                slug,
                clinicName,
                utcNow,
                cancellationToken);
        }

        var existingAdminCount = await accountRepository.CountActiveAdminsByTenantAsync(
            command.TenantId,
            cancellationToken);
        if (existingAdminCount > 0)
        {
            return Result.Failure<ProvisionInitialClinicAdminResult>(InitialAdminAlreadyExists);
        }

        var existingByEmail = await accountRepository.FindByClinicEmailAsync(
            command.TenantId,
            normalizedEmail,
            cancellationToken);
        if (existingByEmail is not null)
        {
            return Result.Failure<ProvisionInitialClinicAdminResult>(StaffManagementPolicy.DuplicateStaffEmail);
        }

        var tempPassword = temporaryPasswordGenerator.Generate();
        var account = IdentityAccount.Create(
            Guid.NewGuid(),
            command.TenantId,
            command.AdminFullName,
            command.AdminEmail,
            passwordHasher.Hash(tempPassword),
            OrgRole.ADMIN_CLINICA,
            active: true,
            specialty: null,
            professionalAttribution: null,
            StaffPermissions.ForAdminClinica(),
            linkedSpecialistIds: null,
            utcNow,
            mustChangePassword: true);

        var record = ProvisioningRecord.CreatePending(
            Guid.NewGuid(),
            command.TenantId,
            cleanRequestId,
            slug,
            clinicName,
            command.AdminFullName,
            command.AdminEmail,
            account.Id,
            utcNow);

        await provisioningRepository.AddWithAccountAsync(record, account, cancellationToken);

        var delivery = await temporaryPasswordDelivery.SendTemporaryPasswordAsync(
            new TemporaryPasswordEmailMessage(
                account.Email,
                account.FullName,
                slug,
                clinicName,
                tempPassword,
                IsInitialClinicAdmin: true),
            cancellationToken);

        if (!delivery.Succeeded)
        {
            record.MarkFailed(account.Id, delivery.ErrorCode ?? EmailDeliveryFailed.Code, clock.UtcNow);
            await provisioningRepository.UpdateAsync(record, cancellationToken);
            return Result.Failure<ProvisionInitialClinicAdminResult>(EmailDeliveryFailed);
        }

        var completedAtUtc = clock.UtcNow;
        record.MarkReady(account.Id, completedAtUtc);
        await provisioningRepository.UpdateAsync(record, cancellationToken);

        return Result.Success(new ProvisionInitialClinicAdminResult(
            record.TenantId,
            record.ProvisioningRequestId,
            account.Id,
            record.Status,
            Gmt6Clock.FormatIsoGmt6(completedAtUtc),
            TemporaryPasswordEmailSent: true));
    }

    private async Task<Result<ProvisionInitialClinicAdminResult>> RetryExistingProvisioningAsync(
        ProvisioningRecord existingRecord,
        string clinicSlug,
        string clinicName,
        DateTimeOffset utcNow,
        CancellationToken cancellationToken)
    {
        IdentityAccount? account = existingRecord.InitialAdminAccountId is Guid accountId
            ? await accountRepository.FindByIdAsync(accountId, cancellationToken)
            : null;

        account ??= await accountRepository.FindByClinicEmailAsync(
            existingRecord.TenantId,
            existingRecord.NormalizedAdminEmail,
            cancellationToken);

        if (account is null)
        {
            return Result.Failure<ProvisionInitialClinicAdminResult>(ProvisioningConflict);
        }

        var freshTempPassword = temporaryPasswordGenerator.Generate();
        account.ChangePassword(passwordHasher.Hash(freshTempPassword), mustChangePassword: true);
        if (!account.Active)
        {
            account.SetActive(true);
        }

        var delivery = await temporaryPasswordDelivery.SendTemporaryPasswordAsync(
            new TemporaryPasswordEmailMessage(
                account.Email,
                account.FullName,
                clinicSlug,
                clinicName,
                freshTempPassword,
                IsInitialClinicAdmin: true),
            cancellationToken);

        if (!delivery.Succeeded)
        {
            existingRecord.MarkFailed(account.Id, delivery.ErrorCode ?? EmailDeliveryFailed.Code, clock.UtcNow);
            await provisioningRepository.UpdateWithAccountAsync(existingRecord, account, cancellationToken);
            return Result.Failure<ProvisionInitialClinicAdminResult>(EmailDeliveryFailed);
        }

        var completedAtUtc = clock.UtcNow;
        existingRecord.MarkReady(account.Id, completedAtUtc);
        await provisioningRepository.UpdateWithAccountAsync(existingRecord, account, cancellationToken);

        return Result.Success(new ProvisionInitialClinicAdminResult(
            existingRecord.TenantId,
            existingRecord.ProvisioningRequestId,
            account.Id,
            existingRecord.Status,
            Gmt6Clock.FormatIsoGmt6(completedAtUtc),
            TemporaryPasswordEmailSent: true));
    }
}
