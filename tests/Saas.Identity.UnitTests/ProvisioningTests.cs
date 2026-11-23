using Saas.Identity.Application.UseCases.Provisioning;
using Saas.Identity.Domain.Policies;
using Saas.Identity.Domain.ValueObjects;
using Saas.Identity.Infrastructure.Security;

namespace Saas.Identity.UnitTests;

public sealed class ProvisioningTests
{
    private static readonly Guid AuroraId = Guid.Parse("10000000-0000-0000-0000-000000000003");

    private static (
        ProvisionInitialClinicAdminUseCase UseCase,
        InMemoryAccountRepo Accounts,
        InMemoryProvisioningRepo Records,
        FakeTenantDatabaseMigrator Migrator,
        FakeEmailDeliveryPort EmailPort,
        Pbkdf2PasswordHasherAdapter Hasher,
        FakeClock Clock)
        CreateFixture()
    {
        var clock = new FakeClock(DateTimeOffset.Parse("2026-11-21T19:00:00Z"));
        var accounts = new InMemoryAccountRepo();
        var records = new InMemoryProvisioningRepo(accounts);
        var migrator = new FakeTenantDatabaseMigrator();
        var hasher = new Pbkdf2PasswordHasherAdapter();
        var tempGen = new TemporaryPasswordGeneratorAdapter();
        var emailPort = new FakeEmailDeliveryPort();

        var useCase = new ProvisionInitialClinicAdminUseCase(
            records,
            accounts,
            migrator,
            hasher,
            tempGen,
            emailPort,
            clock);

        return (useCase, accounts, records, migrator, emailPort, hasher, clock);
    }

    [Fact]
    public async Task ProvisionInitialAdmin_CreatesAccountSendsEmailAndIsIdempotentOnRetry()
    {
        var (useCase, accounts, _, migrator, emailPort, hasher, _) = CreateFixture();
        var cmd = new ProvisionInitialClinicAdminCommand(
            AuroraId,
            "prov-aurora-001",
            "clinica-aurora",
            "Unidad Clínica Aurora",
            "Mtro. Ernesto Cárdenas",
            "admin@aurora.vital.demo");

        var first = await useCase.ExecuteAsync(cmd);

        Assert.True(first.IsSuccess);
        Assert.Equal(ProvisioningRecordStatus.READY, first.Value.Status);
        Assert.True(first.Value.TemporaryPasswordEmailSent);
        Assert.Contains(AuroraId, migrator.MigratedTenants);
        Assert.Single(accounts.Items);
        Assert.Single(emailPort.SentMessages);

        var createdAccount = accounts.Items[0];
        Assert.Equal(OrgRole.ADMIN_CLINICA, createdAccount.Role);
        Assert.True(createdAccount.MustChangePassword);
        Assert.True(PasswordPolicy.Validate(emailPort.SentMessages[0].TemporaryPassword).IsSuccess);
        Assert.True(hasher.Verify(createdAccount.PasswordHash, emailPort.SentMessages[0].TemporaryPassword));

        // Reintento idéntico devuelve exactamente la misma cuenta sin duplicar correo.
        var second = await useCase.ExecuteAsync(cmd);
        Assert.True(second.IsSuccess);
        Assert.Equal(first.Value.InitialAdminAccountId, second.Value.InitialAdminAccountId);
        Assert.Single(accounts.Items);
        Assert.Single(emailPort.SentMessages);
    }

    [Fact]
    public async Task ProvisionInitialAdmin_RejectsPayloadMismatch_WithProvisioningConflict()
    {
        var (useCase, _, _, _, _, _, _) = CreateFixture();
        await useCase.ExecuteAsync(new ProvisionInitialClinicAdminCommand(
            AuroraId, "prov-aurora-001", "clinica-aurora", "Aurora", "Mtro. Ernesto", "admin@aurora.vital.demo"));

        var conflict = await useCase.ExecuteAsync(new ProvisionInitialClinicAdminCommand(
            AuroraId, "prov-aurora-001", "clinica-aurora", "Aurora", "Otro Admin", "otro@aurora.vital.demo"));

        Assert.True(conflict.IsFailure);
        Assert.Equal("PROVISIONING_CONFLICT", conflict.Error.Code);
        Assert.Equal(409, conflict.Error.HttpStatus);
    }

    [Fact]
    public async Task ProvisionInitialAdmin_MarksFailedOnEmailFailure_AndRecoversSameAccountOnRetry()
    {
        var (useCase, accounts, records, _, emailPort, hasher, clock) = CreateFixture();
        emailPort.ShouldFail = true;

        var cmd = new ProvisionInitialClinicAdminCommand(
            AuroraId,
            "prov-aurora-retry",
            "clinica-aurora",
            "Unidad Clínica Aurora",
            "Mtro. Ernesto Cárdenas",
            "admin@aurora.vital.demo");

        var firstAttempt = await useCase.ExecuteAsync(cmd);
        Assert.True(firstAttempt.IsFailure);
        Assert.Equal("EMAIL_DELIVERY_FAILED", firstAttempt.Error.Code);
        Assert.Equal(503, firstAttempt.Error.HttpStatus);
        Assert.Single(accounts.Items);
        Assert.Equal(ProvisioningRecordStatus.FAILED, records.Records[0].Status);

        var originalAccountId = accounts.Items[0].Id;

        // Recuperar entrega de correo y reintentar con el mismo provisioningRequestId.
        emailPort.ShouldFail = false;
        clock.UtcNow = clock.UtcNow.AddMinutes(1);
        var retry = await useCase.ExecuteAsync(cmd);

        Assert.True(retry.IsSuccess);
        Assert.Equal(originalAccountId, retry.Value.InitialAdminAccountId);
        Assert.Equal(ProvisioningRecordStatus.READY, retry.Value.Status);
        Assert.Single(accounts.Items);
        Assert.Single(emailPort.SentMessages);
        Assert.True(hasher.Verify(accounts.Items[0].PasswordHash, emailPort.SentMessages[0].TemporaryPassword));
    }

    [Fact]
    public async Task ProvisionInitialAdmin_BlocksSecondAdminWithDifferentRequestId()
    {
        var (useCase, _, _, _, _, _, _) = CreateFixture();
        await useCase.ExecuteAsync(new ProvisionInitialClinicAdminCommand(
            AuroraId, "prov-aurora-001", "clinica-aurora", "Aurora", "Mtro. Ernesto", "admin@aurora.vital.demo"));

        var secondAdmin = await useCase.ExecuteAsync(new ProvisionInitialClinicAdminCommand(
            AuroraId, "prov-aurora-002", "clinica-aurora", "Aurora", "Segundo Admin", "admin2@aurora.vital.demo"));

        Assert.True(secondAdmin.IsFailure);
        Assert.Equal("INITIAL_ADMIN_ALREADY_EXISTS", secondAdmin.Error.Code);
        Assert.Equal(409, secondAdmin.Error.HttpStatus);
    }

    [Fact]
    public async Task ProvisionInitialAdmin_Returns503_WhenTenantDatabaseUnavailable()
    {
        var (useCase, _, _, migrator, _, _, _) = CreateFixture();
        migrator.ShouldFailUnavailable = true;

        var result = await useCase.ExecuteAsync(new ProvisionInitialClinicAdminCommand(
            AuroraId, "prov-aurora-003", "clinica-aurora", "Aurora", "Mtro. Ernesto", "admin@aurora.vital.demo"));

        Assert.True(result.IsFailure);
        Assert.Equal("TENANT_DATABASE_UNAVAILABLE", result.Error.Code);
        Assert.Equal(503, result.Error.HttpStatus);
    }
}
