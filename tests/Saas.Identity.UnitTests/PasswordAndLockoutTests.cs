using Saas.Identity.Application.UseCases.Auth;
using Saas.Identity.Domain.Entities;
using Saas.Identity.Domain.Policies;
using Saas.Identity.Domain.ValueObjects;
using Saas.Identity.Infrastructure.Security;

namespace Saas.Identity.UnitTests;

public sealed class PasswordAndLockoutTests
{
    private static readonly Guid NorteId = Guid.Parse("10000000-0000-0000-0000-000000000001");

    [Theory]
    [InlineData(null, false)]
    [InlineData("", false)]
    [InlineData("Ab1!", false)] // menor a 8
    [InlineData("Ab1!5678901234567890123456789012345678901", false)] // mayor a 40
    [InlineData("12345678!", false)] // sin letra
    [InlineData("Abcdefgh!", false)] // sin numero
    [InlineData("Abcdefg1", false)] // sin simbolo
    [InlineData("Abcdef 1", false)] // espacio no cuenta como simbolo
    [InlineData("Abcdef1\n!", false)] // caracter de control
    [InlineData("Vital2026!", true)]
    [InlineData("Aa1!aaaa", true)]
    public void PasswordPolicy_EnforcesLengthAndCharacterClasses(string? candidate, bool expectedValid)
    {
        var result = PasswordPolicy.Validate(candidate);

        Assert.Equal(expectedValid, result.IsSuccess);
        if (!expectedValid)
        {
            Assert.Equal("WEAK_PASSWORD", result.Error.Code);
            Assert.Equal(400, result.Error.HttpStatus);
        }
    }

    [Fact]
    public void TemporaryPasswordGenerator_ProducesUniqueCompliantPasswords()
    {
        var generator = new TemporaryPasswordGeneratorAdapter();
        var generated = new HashSet<string>(StringComparer.Ordinal);

        for (var i = 0; i < 20; i++)
        {
            var password = generator.Generate();
            Assert.True(PasswordPolicy.Validate(password).IsSuccess);
            Assert.InRange(password.Length, PasswordPolicy.MinLength, PasswordPolicy.MaxLength);
            generated.Add(password);
        }

        Assert.Equal(20, generated.Count);
    }

    [Fact]
    public async Task LoginClinic_AppliesExponentialLockout_AndResetsOnSuccess()
    {
        var clock = new FakeClock(DateTimeOffset.Parse("2026-11-21T14:00:00Z"));
        var hasher = new Pbkdf2PasswordHasherAdapter();
        var issuer = TestJwtHelper.CreateJwtIssuer();
        var accountRepo = new InMemoryAccountRepo();
        var refreshRepo = new InMemoryRefreshRepo();
        var tenantPort = new FakeTenantPort();

        tenantPort.BySlug["clinica-norte"] = new TenantAccessState(
            NorteId, "clinica-norte", "Clínica Norte", TenantOperationalState.ACTIVA, true, 8, "2026-11-21T08:00:00-06:00");

        var account = IdentityAccount.Create(
            Guid.NewGuid(),
            NorteId,
            "Dra. Sofía Mendoza",
            "dra.mendoza@norte.vital.demo",
            hasher.Hash("Vital2026!"),
            OrgRole.ESPECIALISTA,
            true,
            "Cardiología",
            null,
            StaffPermissions.None,
            null,
            clock.UtcNow);
        accountRepo.Seed(account);

        var useCase = new LoginClinicUseCase(accountRepo, refreshRepo, tenantPort, hasher, issuer, clock);

        var fail1 = await useCase.ExecuteAsync(new LoginClinicCommand("clinica-norte", "dra.mendoza@norte.vital.demo", "Wrong1!"));
        var fail2 = await useCase.ExecuteAsync(new LoginClinicCommand("clinica-norte", "dra.mendoza@norte.vital.demo", "Wrong2!"));
        Assert.Equal(401, fail1.Error.HttpStatus);
        Assert.Equal(401, fail2.Error.HttpStatus);

        var fail3 = await useCase.ExecuteAsync(new LoginClinicCommand("clinica-norte", "dra.mendoza@norte.vital.demo", "Wrong3!"));
        Assert.Equal("ACCOUNT_LOCKED_OUT", fail3.Error.Code);
        Assert.Equal(429, fail3.Error.HttpStatus);
        Assert.Equal(30, fail3.Error.Extensions!["retryAfterSeconds"]);

        // Durante los 30s rechaza incluso con contraseña válida sin extender el contador.
        clock.UtcNow = clock.UtcNow.AddSeconds(10);
        var blockedValid = await useCase.ExecuteAsync(new LoginClinicCommand("clinica-norte", "dra.mendoza@norte.vital.demo", "Vital2026!"));
        Assert.Equal("ACCOUNT_LOCKED_OUT", blockedValid.Error.Code);
        Assert.Equal(20, blockedValid.Error.Extensions!["retryAfterSeconds"]);

        // Vencidos los 30s, un 4to fallo duplica el bloqueo a 60s.
        clock.UtcNow = clock.UtcNow.AddSeconds(21);
        var fail4 = await useCase.ExecuteAsync(new LoginClinicCommand("clinica-norte", "dra.mendoza@norte.vital.demo", "Wrong4!"));
        Assert.Equal("ACCOUNT_LOCKED_OUT", fail4.Error.Code);
        Assert.Equal(60, fail4.Error.Extensions!["retryAfterSeconds"]);

        // Al expirar el bloqueo e ingresar clave correcta, limpia contadores.
        clock.UtcNow = clock.UtcNow.AddSeconds(61);
        var success = await useCase.ExecuteAsync(new LoginClinicCommand("clinica-norte", "dra.mendoza@norte.vital.demo", "Vital2026!"));
        Assert.True(success.IsSuccess);
        Assert.Equal(0, account.FailedLoginAttempts);
        Assert.Null(account.LockoutUntilUtc);
    }

    [Fact]
    public void LockoutPolicy_CapsDurationAtThirtyMinutes()
    {
        var now = DateTimeOffset.Parse("2026-11-21T14:00:00Z");

        var lockout = LockoutPolicy.ComputeLockoutUntil(15, now);

        Assert.NotNull(lockout);
        Assert.Equal(1800, (int)(lockout.Value - now).TotalSeconds);
    }

    [Fact]
    public async Task ChangePassword_ValidatesCurrentAndPolicy_AndClearsMustChangeFlag()
    {
        var clock = new FakeClock(DateTimeOffset.Parse("2026-11-21T14:00:00Z"));
        var hasher = new Pbkdf2PasswordHasherAdapter();
        var accountRepo = new InMemoryAccountRepo();

        var account = IdentityAccount.Create(
            Guid.NewGuid(),
            NorteId,
            "Dr. Temporal",
            "temp@norte.vital.demo",
            hasher.Hash("TempPass1!"),
            OrgRole.ESPECIALISTA,
            true,
            "Cardiología",
            null,
            StaffPermissions.None,
            null,
            clock.UtcNow,
            mustChangePassword: true);
        accountRepo.Seed(account);

        var useCase = new ChangePasswordUseCase(accountRepo, hasher);

        var wrongCurrent = await useCase.ExecuteAsync(
            new ChangePasswordCommand(IdentityStoreScope.ForTenant(NorteId), account.Id, "BadCurrent1!", "NuevaClave2026!"));
        Assert.Equal(401, wrongCurrent.Error.HttpStatus);

        var weakNew = await useCase.ExecuteAsync(
            new ChangePasswordCommand(IdentityStoreScope.ForTenant(NorteId), account.Id, "TempPass1!", "debil"));
        Assert.Equal("WEAK_PASSWORD", weakNew.Error.Code);

        var ok = await useCase.ExecuteAsync(
            new ChangePasswordCommand(IdentityStoreScope.ForTenant(NorteId), account.Id, "TempPass1!", "NuevaClave2026!"));
        Assert.True(ok.IsSuccess);
        Assert.False(account.MustChangePassword);
        Assert.True(hasher.Verify(account.PasswordHash, "NuevaClave2026!"));
    }
}
