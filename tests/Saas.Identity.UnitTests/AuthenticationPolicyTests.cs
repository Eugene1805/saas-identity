using Saas.Identity.Domain.Entities;
using Saas.Identity.Domain.Policies;
using Saas.Identity.Domain.ValueObjects;

namespace Saas.Identity.UnitTests;

public sealed class AuthenticationPolicyTests
{
    private static readonly Guid NorteId = Guid.Parse("10000000-0000-0000-0000-000000000001");
    private static readonly Guid ValleId = Guid.Parse("10000000-0000-0000-0000-000000000002");

    private static TenantAccessState BuildTenant(Guid id, string slug, TenantOperationalState state) =>
        new(id, slug, slug, state, state == TenantOperationalState.ACTIVA, 8, "2026-11-21T08:00:00-06:00");

    private static IdentityAccount BuildAccount(
        Guid? tenantId,
        string email,
        OrgRole role,
        bool active = true) =>
        IdentityAccount.Create(
            Guid.NewGuid(),
            tenantId,
            "Usuario Demo",
            email,
            "pbkdf2-sha256$100000$aaa$bbb",
            role,
            active,
            null,
            null,
            StaffPermissions.None,
            null,
            DateTimeOffset.UtcNow);

    [Fact]
    public void ClinicLogin_FailsClosed_WhenPlatformUnavailable()
    {
        var result = AuthenticationPolicy.ValidateClinicLogin(null, true, null, false);

        Assert.True(result.IsFailure);
        Assert.Equal("TENANT_STATE_UNAVAILABLE", result.Error.Code);
        Assert.Equal(503, result.Error.HttpStatus);
    }

    [Fact]
    public void ClinicLogin_DeniesPendingAdminAndSuspendedTenants()
    {
        var pending = BuildTenant(NorteId, "clinica-aurora", TenantOperationalState.PENDIENTE_ADMIN);
        var suspended = BuildTenant(ValleId, "clinica-valle", TenantOperationalState.SUSPENDIDA);

        var pendingResult = AuthenticationPolicy.ValidateClinicLogin(pending, false, null, false);
        var suspendedResult = AuthenticationPolicy.ValidateClinicLogin(suspended, false, null, false);

        Assert.Equal("TENANT_PENDING_ADMIN", pendingResult.Error.Code);
        Assert.Equal(403, pendingResult.Error.HttpStatus);
        Assert.Equal("TENANT_SUSPENDED", suspendedResult.Error.Code);
        Assert.Equal(403, suspendedResult.Error.HttpStatus);
    }

    [Fact]
    public void ClinicLogin_DeniesCrossTenantAndSuperAdminAccounts()
    {
        var norte = BuildTenant(NorteId, "clinica-norte", TenantOperationalState.ACTIVA);
        var valleAccount = BuildAccount(ValleId, "dra@valle.demo", OrgRole.ESPECIALISTA);
        var superAdmin = BuildAccount(null, "super@vital.demo", OrgRole.SUPER_ADMIN);

        var crossTenant = AuthenticationPolicy.ValidateClinicLogin(norte, false, valleAccount, true);
        var platformOnClinic = AuthenticationPolicy.ValidateClinicLogin(norte, false, superAdmin, true);

        Assert.Equal("INVALID_CREDENTIALS", crossTenant.Error.Code);
        Assert.Equal(401, crossTenant.Error.HttpStatus);
        Assert.Equal("INVALID_CREDENTIALS", platformOnClinic.Error.Code);
    }

    [Fact]
    public void ClinicLogin_DeniesDisabledAccount()
    {
        var norte = BuildTenant(NorteId, "clinica-norte", TenantOperationalState.ACTIVA);
        var disabled = BuildAccount(NorteId, "dr.vega@norte.demo", OrgRole.ESPECIALISTA, active: false);

        var result = AuthenticationPolicy.ValidateClinicLogin(norte, false, disabled, true);

        Assert.True(result.IsFailure);
        Assert.Equal("ACCOUNT_DISABLED", result.Error.Code);
        Assert.Equal(403, result.Error.HttpStatus);
    }

    [Fact]
    public void PlatformLogin_RequiresActiveSuperAdminWithoutTenant()
    {
        var superAdmin = BuildAccount(null, "super@vital.demo", OrgRole.SUPER_ADMIN, active: true);
        var clinicAdmin = BuildAccount(NorteId, "admin@norte.demo", OrgRole.ADMIN_CLINICA, active: true);

        Assert.True(AuthenticationPolicy.ValidatePlatformLogin(superAdmin, true).IsSuccess);
        Assert.Equal("INVALID_CREDENTIALS", AuthenticationPolicy.ValidatePlatformLogin(clinicAdmin, true).Error.Code);
        Assert.Equal("INVALID_CREDENTIALS", AuthenticationPolicy.ValidatePlatformLogin(superAdmin, false).Error.Code);
    }
}
