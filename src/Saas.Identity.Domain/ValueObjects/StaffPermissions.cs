namespace Saas.Identity.Domain.ValueObjects;

public sealed record StaffPermissions(
    bool CanPrescribe,
    bool CanRegisterPatients,
    bool CanAssignInitialPrimary,
    bool CanUploadStudies)
{
    public static StaffPermissions None => new(false, false, false, false);

    public static StaffPermissions ForAdminClinica() => new(false, true, true, false);
}
