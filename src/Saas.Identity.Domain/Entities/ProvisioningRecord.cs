using Saas.Identity.Domain.ValueObjects;

namespace Saas.Identity.Domain.Entities;

public sealed class ProvisioningRecord
{
    private ProvisioningRecord()
    {
        ProvisioningRequestId = string.Empty;
        ClinicSlug = string.Empty;
        ClinicName = string.Empty;
        AdminFullName = string.Empty;
        AdminEmail = string.Empty;
        NormalizedAdminEmail = string.Empty;
    }

    private ProvisioningRecord(
        Guid id,
        Guid tenantId,
        string provisioningRequestId,
        string clinicSlug,
        string clinicName,
        string adminFullName,
        string adminEmail,
        Guid? initialAdminAccountId,
        ProvisioningRecordStatus status,
        DateTimeOffset createdAtUtc)
    {
        Id = id;
        TenantId = tenantId;
        ProvisioningRequestId = provisioningRequestId.Trim();
        ClinicSlug = clinicSlug.Trim().ToLowerInvariant();
        ClinicName = clinicName.Trim();
        AdminFullName = adminFullName.Trim();
        AdminEmail = adminEmail.Trim();
        NormalizedAdminEmail = IdentityAccount.NormalizeEmail(adminEmail);
        InitialAdminAccountId = initialAdminAccountId;
        Status = status;
        TemporaryPasswordEmailSent = false;
        CreatedAtUtc = createdAtUtc.ToUniversalTime();
        UpdatedAtUtc = CreatedAtUtc;
    }

    public Guid Id { get; private set; }
    public Guid TenantId { get; private set; }
    public string ProvisioningRequestId { get; private set; }
    public string ClinicSlug { get; private set; }
    public string ClinicName { get; private set; }
    public string AdminFullName { get; private set; }
    public string AdminEmail { get; private set; }
    public string NormalizedAdminEmail { get; private set; }
    public Guid? InitialAdminAccountId { get; private set; }
    public ProvisioningRecordStatus Status { get; private set; }
    public bool TemporaryPasswordEmailSent { get; private set; }
    public string? LastErrorCode { get; private set; }
    public DateTimeOffset CreatedAtUtc { get; private set; }
    public DateTimeOffset UpdatedAtUtc { get; private set; }

    public static ProvisioningRecord CreatePending(
        Guid id,
        Guid tenantId,
        string provisioningRequestId,
        string clinicSlug,
        string clinicName,
        string adminFullName,
        string adminEmail,
        Guid? initialAdminAccountId,
        DateTimeOffset utcNow)
    {
        if (tenantId == Guid.Empty)
        {
            throw new ArgumentException("El tenantId es obligatorio.", nameof(tenantId));
        }

        if (string.IsNullOrWhiteSpace(provisioningRequestId))
        {
            throw new ArgumentException("El provisioningRequestId es obligatorio.", nameof(provisioningRequestId));
        }

        return new ProvisioningRecord(
            id,
            tenantId,
            provisioningRequestId,
            clinicSlug,
            clinicName,
            adminFullName,
            adminEmail,
            initialAdminAccountId,
            ProvisioningRecordStatus.PENDING_ACTIVATION,
            utcNow);
    }

    public bool MatchesPayload(Guid tenantId, string normalizedEmail, string adminFullName) =>
        TenantId == tenantId &&
        NormalizedAdminEmail == normalizedEmail &&
        string.Equals(AdminFullName, adminFullName.Trim(), StringComparison.OrdinalIgnoreCase);

    public void MarkReady(Guid adminAccountId, DateTimeOffset utcNow)
    {
        InitialAdminAccountId = adminAccountId;
        Status = ProvisioningRecordStatus.READY;
        TemporaryPasswordEmailSent = true;
        LastErrorCode = null;
        UpdatedAtUtc = utcNow.ToUniversalTime();
    }

    public void MarkFailed(Guid? adminAccountId, string errorCode, DateTimeOffset utcNow)
    {
        if (adminAccountId is not null)
        {
            InitialAdminAccountId = adminAccountId;
        }

        Status = ProvisioningRecordStatus.FAILED;
        TemporaryPasswordEmailSent = false;
        LastErrorCode = string.IsNullOrWhiteSpace(errorCode) ? "PROVISIONING_FAILED" : errorCode.Trim();
        UpdatedAtUtc = utcNow.ToUniversalTime();
    }
}
