using Saas.Identity.Application.UseCases.Auth;
using Saas.Identity.Domain.Common;
using Saas.Identity.Domain.Entities;
using Saas.Identity.Domain.ValueObjects;
using Saas.Identity.Infrastructure.Security;

namespace Saas.Identity.UnitTests;

public sealed class AuthUseCasesTests
{
    private static readonly Guid NorteId = Guid.Parse("10000000-0000-0000-0000-000000000001");
    private static readonly Guid ValleId = Guid.Parse("10000000-0000-0000-0000-000000000002");

    private static JwtTokenIssuerAdapter CreateJwtIssuer() => TestJwtHelper.CreateJwtIssuer();

    [Fact]
    public async Task LoginClinic_IssuesJwtAndPersistsHashedRefreshTokenInGmt6()
    {
        var clock = new FakeClock(DateTimeOffset.Parse("2026-11-21T14:00:00Z")); // 08:00:00-06:00
        var hasher = new Pbkdf2PasswordHasherAdapter();
        var issuer = CreateJwtIssuer();
        var accountRepo = new InMemoryAccountRepo();
        var refreshRepo = new InMemoryRefreshRepo();
        var tenantPort = new FakeTenantPort();

        tenantPort.BySlug["clinica-norte"] = new TenantAccessState(
            NorteId, "clinica-norte", "Clínica Norte", TenantOperationalState.ACTIVA, true, 8, "2026-11-21T08:00:00-06:00");

        var mendoza = IdentityAccount.Create(
            Guid.NewGuid(),
            NorteId,
            "Dra. Sofía Mendoza",
            "dra.mendoza@norte.vital.demo",
            hasher.Hash("Vital2026!"),
            OrgRole.ESPECIALISTA,
            true,
            "Cardiología",
            new ProfessionalAttribution("CED-FICT-4012", "Cardióloga", "2026-11-10T09:30:00-06:00"),
            new StaffPermissions(true, true, false, false),
            null,
            clock.UtcNow);
        accountRepo.Items.Add(mendoza);

        var useCase = new LoginClinicUseCase(accountRepo, refreshRepo, tenantPort, hasher, issuer, clock);
        var result = await useCase.ExecuteAsync(new LoginClinicCommand("clinica-norte", "dra.mendoza@norte.vital.demo", "Vital2026!"));

        Assert.True(result.IsSuccess);
        Assert.Equal("Bearer", result.Value.TokenType);
        Assert.Equal("2026-11-21T08:15:00-06:00", result.Value.AccessTokenExpiresAtGmt6);
        Assert.Equal("2026-11-28T08:00:00-06:00", result.Value.RefreshTokenExpiresAtGmt6);
        Assert.Single(refreshRepo.Sessions);
        Assert.NotEqual(result.Value.RefreshToken, refreshRepo.Sessions[0].TokenHash);
    }

    [Fact]
    public async Task RefreshSession_RotatesToken_AndDetectsReuseToRevokeAllSessions()
    {
        var clock = new FakeClock(DateTimeOffset.Parse("2026-11-21T14:00:00Z"));
        var hasher = new Pbkdf2PasswordHasherAdapter();
        var issuer = CreateJwtIssuer();
        var accountRepo = new InMemoryAccountRepo();
        var refreshRepo = new InMemoryRefreshRepo();
        var tenantPort = new FakeTenantPort();

        tenantPort.BySlug["clinica-norte"] = new TenantAccessState(
            NorteId, "clinica-norte", "Clínica Norte", TenantOperationalState.ACTIVA, true, 8, "2026-11-21T08:00:00-06:00");

        var admin = IdentityAccount.Create(
            Guid.NewGuid(),
            NorteId,
            "Lic. Mariana Paredes",
            "admin@norte.vital.demo",
            hasher.Hash("Vital2026!"),
            OrgRole.ADMIN_CLINICA,
            true,
            null,
            null,
            StaffPermissions.ForAdminClinica(),
            null,
            clock.UtcNow);
        accountRepo.Items.Add(admin);

        var login = new LoginClinicUseCase(accountRepo, refreshRepo, tenantPort, hasher, issuer, clock);
        var firstAuth = await login.ExecuteAsync(new LoginClinicCommand("clinica-norte", "admin@norte.vital.demo", "Vital2026!"));
        var refreshUseCase = new RefreshSessionUseCase(accountRepo, refreshRepo, tenantPort, issuer, clock);

        clock.UtcNow = clock.UtcNow.AddMinutes(5);
        var rotated = await refreshUseCase.ExecuteAsync(new RefreshSessionCommand(firstAuth.Value.RefreshToken));
        Assert.True(rotated.IsSuccess);
        Assert.NotEqual(firstAuth.Value.RefreshToken, rotated.Value.RefreshToken);
        Assert.Equal(2, refreshRepo.Sessions.Count);

        // Reutilización del primer refresh token: revoca incluso el nuevo token activo.
        clock.UtcNow = clock.UtcNow.AddMinutes(1);
        var reuseAttempt = await refreshUseCase.ExecuteAsync(new RefreshSessionCommand(firstAuth.Value.RefreshToken));
        Assert.True(reuseAttempt.IsFailure);
        Assert.Equal("REFRESH_TOKEN_REVOKED", reuseAttempt.Error.Code);
        Assert.All(refreshRepo.Sessions, s => Assert.True(s.IsRevoked));
    }

    [Fact]
    public async Task RefreshSession_DeniesWhenTenantIsSuspendedOrExpired()
    {
        var clock = new FakeClock(DateTimeOffset.Parse("2026-11-21T14:00:00Z"));
        var hasher = new Pbkdf2PasswordHasherAdapter();
        var issuer = CreateJwtIssuer();
        var accountRepo = new InMemoryAccountRepo();
        var refreshRepo = new InMemoryRefreshRepo();
        var tenantPort = new FakeTenantPort();

        tenantPort.BySlug["clinica-valle"] = new TenantAccessState(
            ValleId, "clinica-valle", "Consultorios del Valle", TenantOperationalState.ACTIVA, true, 4, "2026-11-21T08:00:00-06:00");

        var admin = IdentityAccount.Create(
            Guid.NewGuid(),
            ValleId,
            "Ing. Rodrigo Téllez",
            "admin@valle.vital.demo",
            hasher.Hash("Vital2026!"),
            OrgRole.ADMIN_CLINICA,
            true,
            null,
            null,
            StaffPermissions.ForAdminClinica(),
            null,
            clock.UtcNow);
        accountRepo.Items.Add(admin);

        var login = await new LoginClinicUseCase(accountRepo, refreshRepo, tenantPort, hasher, issuer, clock)
            .ExecuteAsync(new LoginClinicCommand("clinica-valle", "admin@valle.vital.demo", "Vital2026!"));
        Assert.True(login.IsSuccess);

        // Suspender clínica después de haber emitido sesión
        tenantPort.BySlug["clinica-valle"] = tenantPort.BySlug["clinica-valle"]! with
        {
            State = TenantOperationalState.SUSPENDIDA,
            MayAuthenticate = false,
        };

        var refreshUseCase = new RefreshSessionUseCase(accountRepo, refreshRepo, tenantPort, issuer, clock);
        var suspendedRefresh = await refreshUseCase.ExecuteAsync(new RefreshSessionCommand(login.Value.RefreshToken));
        Assert.Equal("TENANT_SUSPENDED", suspendedRefresh.Error.Code);
        Assert.Equal(403, suspendedRefresh.Error.HttpStatus);

        // Reactivar pero hacer vencer el refresh token (> 7 días)
        tenantPort.BySlug["clinica-valle"] = tenantPort.BySlug["clinica-valle"]! with
        {
            State = TenantOperationalState.ACTIVA,
            MayAuthenticate = true,
        };
        clock.UtcNow = clock.UtcNow.AddDays(8);
        var expiredRefresh = await refreshUseCase.ExecuteAsync(new RefreshSessionCommand(login.Value.RefreshToken));
        Assert.Equal("REFRESH_TOKEN_EXPIRED", expiredRefresh.Error.Code);
    }

    [Fact]
    public async Task Logout_RevokesRefreshTokenIdempotently_AndBlocksFurtherRefresh()
    {
        var clock = new FakeClock(DateTimeOffset.Parse("2026-11-21T14:00:00Z"));
        var hasher = new Pbkdf2PasswordHasherAdapter();
        var issuer = CreateJwtIssuer();
        var accountRepo = new InMemoryAccountRepo();
        var refreshRepo = new InMemoryRefreshRepo();
        var tenantPort = new FakeTenantPort();

        var superAdmin = IdentityAccount.Create(
            Guid.NewGuid(),
            null,
            "SuperAdmin",
            "superadmin@vital.demo",
            hasher.Hash("Vital2026!"),
            OrgRole.SUPER_ADMIN,
            true,
            null,
            null,
            StaffPermissions.None,
            null,
            clock.UtcNow);
        accountRepo.Items.Add(superAdmin);

        var auth = await new LoginPlatformUseCase(accountRepo, refreshRepo, hasher, issuer, clock)
            .ExecuteAsync(new LoginPlatformCommand("superadmin@vital.demo", "Vital2026!"));
        Assert.True(auth.IsSuccess);

        var logout = new LogoutUseCase(refreshRepo, issuer, clock);
        Assert.True((await logout.ExecuteAsync(new LogoutCommand(auth.Value.RefreshToken))).IsSuccess);
        Assert.True((await logout.ExecuteAsync(new LogoutCommand(auth.Value.RefreshToken))).IsSuccess);

        var afterLogout = await new RefreshSessionUseCase(accountRepo, refreshRepo, tenantPort, issuer, clock)
            .ExecuteAsync(new RefreshSessionCommand(auth.Value.RefreshToken));
        Assert.Equal("REFRESH_TOKEN_REVOKED", afterLogout.Error.Code);
        Assert.Equal("2026-11-21T08:00:00-06:00", Gmt6Clock.FormatIsoGmt6(clock.UtcNow));
    }
}
