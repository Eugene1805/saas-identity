using Saas.Identity.Domain.ValueObjects;

namespace Saas.Identity.Application.UseCases.Provisioning;

public sealed record ProvisionInitialClinicAdminCommand(
    Guid TenantId,
    string ProvisioningRequestId,
    string ClinicSlug,
    string ClinicName,
    string AdminFullName,
    string AdminEmail);

public sealed record ProvisionInitialClinicAdminResult(
    Guid TenantId,
    string ProvisioningRequestId,
    Guid InitialAdminAccountId,
    ProvisioningRecordStatus Status,
    string EvaluatedAtGmt6,
    bool TemporaryPasswordEmailSent);
