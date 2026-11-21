using Saas.Identity.Domain.Policies;
using Saas.Identity.Domain.ValueObjects;

namespace Saas.Identity.Domain.Entities;

public sealed class IdentityAccount
{
    private readonly List<Guid> _linkedSpecialistIds = [];

    private IdentityAccount()
    {
        FullName = string.Empty;
        Email = string.Empty;
        NormalizedEmail = string.Empty;
        PasswordHash = string.Empty;
        Permissions = StaffPermissions.None;
    }

    private IdentityAccount(
        Guid id,
        Guid? tenantId,
        string fullName,
        string email,
        string passwordHash,
        OrgRole role,
        bool active,
        string? specialty,
        ProfessionalAttribution? professionalAttribution,
        StaffPermissions permissions,
        IEnumerable<Guid>? linkedSpecialistIds,
        DateTimeOffset createdAtUtc,
        bool mustChangePassword)
    {
        Id = id;
        TenantId = tenantId;
        FullName = fullName.Trim();
        Email = email.Trim();
        NormalizedEmail = NormalizeEmail(email);
        PasswordHash = passwordHash;
        Role = role;
        Active = active;
        MustChangePassword = mustChangePassword;
        FailedLoginAttempts = 0;
        LockoutUntilUtc = null;
        Specialty = string.IsNullOrWhiteSpace(specialty) ? null : specialty.Trim();
        ProfessionalAttribution = professionalAttribution;
        Permissions = permissions;
        CreatedAtUtc = createdAtUtc.ToUniversalTime();

        if (linkedSpecialistIds is not null)
        {
            _linkedSpecialistIds.AddRange(linkedSpecialistIds.Distinct());
        }
    }

    public Guid Id { get; private set; }
    public Guid? TenantId { get; private set; }
    public string FullName { get; private set; }
    public string Email { get; private set; }
    public string NormalizedEmail { get; private set; }
    public string PasswordHash { get; private set; }
    public OrgRole Role { get; private set; }
    public bool Active { get; private set; }
    public bool MustChangePassword { get; private set; }
    public int FailedLoginAttempts { get; private set; }
    public DateTimeOffset? LockoutUntilUtc { get; private set; }
    public string? Specialty { get; private set; }
    public ProfessionalAttribution? ProfessionalAttribution { get; private set; }
    public StaffPermissions Permissions { get; private set; }
    public IReadOnlyList<Guid> LinkedSpecialistIds => _linkedSpecialistIds;
    public DateTimeOffset CreatedAtUtc { get; private set; }

    public static string NormalizeEmail(string email) => email.Trim().ToUpperInvariant();

    public static IdentityAccount Create(
        Guid id,
        Guid? tenantId,
        string fullName,
        string email,
        string passwordHash,
        OrgRole role,
        bool active,
        string? specialty,
        ProfessionalAttribution? professionalAttribution,
        StaffPermissions permissions,
        IEnumerable<Guid>? linkedSpecialistIds,
        DateTimeOffset createdAtUtc,
        bool mustChangePassword = false)
    {
        if (role == OrgRole.SUPER_ADMIN && tenantId is not null)
        {
            throw new ArgumentException("Una cuenta SUPER_ADMIN no puede pertenecer a un tenant.", nameof(tenantId));
        }

        if (role != OrgRole.SUPER_ADMIN && tenantId is null)
        {
            throw new ArgumentException("Toda cuenta operativa de clínica debe pertenecer a un tenant.", nameof(tenantId));
        }

        if (string.IsNullOrWhiteSpace(email))
        {
            throw new ArgumentException("El correo electrónico es obligatorio.", nameof(email));
        }

        if (string.IsNullOrWhiteSpace(fullName))
        {
            throw new ArgumentException("El nombre completo es obligatorio.", nameof(fullName));
        }

        return new IdentityAccount(
            id,
            tenantId,
            fullName,
            email,
            passwordHash,
            role,
            active,
            specialty,
            professionalAttribution,
            permissions,
            linkedSpecialistIds,
            createdAtUtc,
            mustChangePassword);
    }

    public bool IsLockedOut(DateTimeOffset utcNow) =>
        LockoutUntilUtc.HasValue && LockoutUntilUtc.Value > utcNow.ToUniversalTime();

    public void RecordFailedLogin(DateTimeOffset utcNow)
    {
        FailedLoginAttempts++;
        LockoutUntilUtc = LockoutPolicy.ComputeLockoutUntil(FailedLoginAttempts, utcNow);
    }

    public void ResetLoginFailures()
    {
        FailedLoginAttempts = 0;
        LockoutUntilUtc = null;
    }

    public void ChangePassword(string newPasswordHash, bool mustChangePassword = false)
    {
        if (string.IsNullOrWhiteSpace(newPasswordHash))
        {
            throw new ArgumentException("El hash de contraseña es obligatorio.", nameof(newPasswordHash));
        }

        PasswordHash = newPasswordHash;
        MustChangePassword = mustChangePassword;
        ResetLoginFailures();
    }

    public void UpdateRoleAndPermissions(
        OrgRole nextRole,
        string? specialty,
        ProfessionalAttribution? attribution,
        StaffPermissions permissions)
    {
        if (nextRole == OrgRole.SUPER_ADMIN)
        {
            throw new ArgumentException("No se puede asignar rol SUPER_ADMIN dentro de un tenant.", nameof(nextRole));
        }

        Role = nextRole;
        Specialty = nextRole == OrgRole.ESPECIALISTA
            ? (string.IsNullOrWhiteSpace(specialty) ? "Medicina General" : specialty.Trim())
            : null;
        ProfessionalAttribution = nextRole == OrgRole.ESPECIALISTA ? attribution : null;
        Permissions = permissions;

        if (nextRole != OrgRole.AUXILIAR)
        {
            _linkedSpecialistIds.Clear();
        }
    }

    public void SetActive(bool active)
    {
        Active = active;
        if (active)
        {
            ResetLoginFailures();
        }
    }

    public void UpdateLinkedSpecialists(IEnumerable<Guid> specialistIds)
    {
        _linkedSpecialistIds.Clear();
        _linkedSpecialistIds.AddRange(specialistIds.Distinct());
    }
}
