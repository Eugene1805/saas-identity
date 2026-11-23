using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using Grpc.Core;
using Grpc.Net.Client;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Npgsql;
using Saas.Contracts.PlatformIdentity.V1;
using Saas.Identity.Api.Grpc;
using Saas.Identity.Application.UseCases.Auth;
using Saas.Identity.Application.UseCases.Provisioning;
using Saas.Identity.Application.UseCases.Staff;
using Saas.Identity.Domain.ValueObjects;

namespace Saas.Identity.IntegrationTests;

public sealed class MultiTenantIsolationIntegrationTests(MultiPostgresFixture fixture)
    : IClassFixture<MultiPostgresFixture>
{
    private sealed class DummyServerCallContext : ServerCallContext
    {
        private readonly Metadata _headers;

        public DummyServerCallContext(Metadata headers)
        {
            _headers = headers;
        }

        protected override string MethodCore => "ProvisionInitialClinicAdmin";
        protected override string HostCore => "localhost";
        protected override string PeerCore => "127.0.0.1";
        protected override DateTime DeadlineCore => DateTime.UtcNow.AddMinutes(1);
        protected override Metadata RequestHeadersCore => _headers;
        protected override CancellationToken CancellationTokenCore => CancellationToken.None;
        protected override Metadata ResponseTrailersCore => new();
        protected override Status StatusCore { get; set; }
        protected override WriteOptions? WriteOptionsCore { get; set; }
        protected override AuthContext AuthContextCore => new(null, new Dictionary<string, List<AuthProperty>>());
        protected override ContextPropagationToken CreatePropagationTokenCore(ContextPropagationOptions? options) =>
            throw new NotSupportedException();
        protected override Task WriteResponseHeadersAsyncCore(Metadata responseHeaders) => Task.CompletedTask;
    }

    [Fact]
    public async Task SameEmailAcrossTwoClinics_UsesCompletelySeparatePostgresInstances_AndIsolatesAllAuthAndStaffOperations()
    {
        await using var factory = fixture.CreateFactory();
        var client = factory.CreateDefaultClient();

        using var channel = GrpcChannel.ForAddress(
            client.BaseAddress!,
            new GrpcChannelOptions { HttpClient = client });
        var grpcClient = new IdentityProvisioningService.IdentityProvisioningServiceClient(channel);
        var grpcHeaders = new Metadata
        {
            { "x-internal-service-key", MultiPostgresFixture.InternalGrpcKey },
        };

        // 1. Aprovisionar Clínica A y Clínica B (cada una en su propia instancia PostgreSQL 17).
        var provA = await grpcClient.ProvisionInitialClinicAdminAsync(
            new ProvisionInitialClinicAdminRequest
            {
                TenantId = MultiPostgresFixture.ClinicAId.ToString(),
                ProvisioningRequestId = $"prov-alfa-{Guid.NewGuid():N}",
                ClinicSlug = MultiPostgresFixture.ClinicASlug,
                ClinicName = "Clínica Alfa",
                AdminFullName = "Admin Alfa",
                AdminEmail = "admin.alfa@vital.demo",
            },
            grpcHeaders);
        Assert.Equal(ProvisioningStatus.Ready, provA.Status);

        var provB = await grpcClient.ProvisionInitialClinicAdminAsync(
            new ProvisionInitialClinicAdminRequest
            {
                TenantId = MultiPostgresFixture.ClinicBId.ToString(),
                ProvisioningRequestId = $"prov-beta-{Guid.NewGuid():N}",
                ClinicSlug = MultiPostgresFixture.ClinicBSlug,
                ClinicName = "Clínica Beta",
                AdminFullName = "Admin Beta",
                AdminEmail = "admin.beta@vital.demo",
            },
            grpcHeaders);
        Assert.Equal(ProvisioningStatus.Ready, provB.Status);

        // 2. SuperAdmin se autentica exclusivamente en BD Global y da de alta misma cuenta? No, cada AdminClinica crea el mismo email en SU clínica.
        // Para conocer las claves iniciales de Admin Alfa/Beta en test, asignamos una cuenta especialista con contraseña conocida?
        // Nota: como ProvisionInitialClinicAdmin genera clave aleatoria enviada por email (LogOnly),
        // verificamos primero SuperAdmin en BD Global y creamos Admin secundario o especialista con el MISMO correo en Alfa y Beta
        // usando AdminClinica? Espera: obtenemos acceso de AdminClinica mediante el repositorio en su scope exclusivo de test o un scope aislado.
        Guid adminAId = Guid.Parse(provA.InitialAdminAccountId);
        Guid adminBId = Guid.Parse(provB.InitialAdminAccountId);

        using var scope = factory.Services.CreateScope();
        var createStaff = scope.ServiceProvider.GetRequiredService<CreateStaffUseCase>();

        const string sharedEmail = "dra.compartida@vital.demo";
        const string passA = "ClinicaAlfa#2026";
        const string passB = "ClinicaBeta#2026";

        var createdA = await createStaff.ExecuteAsync(new CreateStaffCommand(
            IdentityStoreScope.ForTenant(MultiPostgresFixture.ClinicAId),
            adminAId,
            "Dra. Compartida Alfa",
            sharedEmail,
            passA,
            GenerateTemporaryPassword: false,
            "ESPECIALISTA",
            "Cardiología",
            "CED-A-01",
            "Cardióloga",
            new StaffPermissions(true, true, false, false)));
        Assert.True(createdA.IsSuccess);

        var createdB = await createStaff.ExecuteAsync(new CreateStaffCommand(
            IdentityStoreScope.ForTenant(MultiPostgresFixture.ClinicBId),
            adminBId,
            "Dra. Compartida Beta",
            sharedEmail,
            passB,
            GenerateTemporaryPassword: false,
            "ESPECIALISTA",
            "Pediatría",
            "CED-B-02",
            "Pediatra",
            new StaffPermissions(false, true, false, false)));
        Assert.True(createdB.IsSuccess);

        Assert.NotEqual(createdA.Value.Account.Id, createdB.Value.Account.Id);

        // 3. Autenticación cruzada: contraseña de B falla en A y viceversa.
        var badLoginA = await client.PostAsJsonAsync("/v1/auth/login", new
        {
            clinicSlug = MultiPostgresFixture.ClinicASlug,
            email = sharedEmail,
            password = passB,
        });
        Assert.Equal(HttpStatusCode.Unauthorized, badLoginA.StatusCode);

        var badLoginB = await client.PostAsJsonAsync("/v1/auth/login", new
        {
            clinicSlug = MultiPostgresFixture.ClinicBSlug,
            email = sharedEmail,
            password = passA,
        });
        Assert.Equal(HttpStatusCode.Unauthorized, badLoginB.StatusCode);

        var loginAResp = await client.PostAsJsonAsync("/v1/auth/login", new
        {
            clinicSlug = MultiPostgresFixture.ClinicASlug,
            email = sharedEmail,
            password = passA,
        });
        Assert.Equal(HttpStatusCode.OK, loginAResp.StatusCode);
        var sessionA = await loginAResp.Content.ReadFromJsonAsync<AuthSessionResult>();
        Assert.NotNull(sessionA);
        Assert.Equal(createdA.Value.Account.Id, sessionA!.Account.Id);
        Assert.Equal(MultiPostgresFixture.ClinicAId, sessionA.Account.TenantId);

        var loginBResp = await client.PostAsJsonAsync("/v1/auth/login", new
        {
            clinicSlug = MultiPostgresFixture.ClinicBSlug,
            email = sharedEmail,
            password = passB,
        });
        Assert.Equal(HttpStatusCode.OK, loginBResp.StatusCode);
        var sessionB = await loginBResp.Content.ReadFromJsonAsync<AuthSessionResult>();
        Assert.NotNull(sessionB);
        Assert.Equal(createdB.Value.Account.Id, sessionB!.Account.Id);
        Assert.Equal(MultiPostgresFixture.ClinicBId, sessionB.Account.TenantId);

        // 4. Refresh, /v1/auth/me, manipulación de refresh token entre tenants y change-password solo afectan su propia BD.
        var tamperedRefreshToken = sessionA.RefreshToken.Replace(
            MultiPostgresFixture.ClinicAId.ToString("N"),
            MultiPostgresFixture.ClinicBId.ToString("N"),
            StringComparison.Ordinal);
        var tamperedRefreshResp = await client.PostAsJsonAsync("/v1/auth/refresh", new
        {
            refreshToken = tamperedRefreshToken,
        });
        Assert.Equal(HttpStatusCode.Unauthorized, tamperedRefreshResp.StatusCode);

        var refreshAResp = await client.PostAsJsonAsync("/v1/auth/refresh", new
        {
            refreshToken = sessionA.RefreshToken,
        });
        Assert.Equal(HttpStatusCode.OK, refreshAResp.StatusCode);
        var refreshedA = await refreshAResp.Content.ReadFromJsonAsync<AuthSessionResult>();
        Assert.NotNull(refreshedA);

        const string newPassA = "NuevaAlfa#2027";
        using (var changePassReq = new HttpRequestMessage(HttpMethod.Post, "/v1/auth/change-password"))
        {
            changePassReq.Headers.Authorization = new AuthenticationHeaderValue("Bearer", refreshedA!.AccessToken);
            changePassReq.Content = JsonContent.Create(new { currentPassword = passA, newPassword = newPassA });
            var changePassResp = await client.SendAsync(changePassReq);
            Assert.Equal(HttpStatusCode.NoContent, changePassResp.StatusCode);
        }

        // Cuenta en B sigue usando passB intacta; A requiere newPassA.
        var reLoginBResp = await client.PostAsJsonAsync("/v1/auth/login", new
        {
            clinicSlug = MultiPostgresFixture.ClinicBSlug,
            email = sharedEmail,
            password = passB,
        });
        Assert.Equal(HttpStatusCode.OK, reLoginBResp.StatusCode);

        var logoutAResp = await client.PostAsJsonAsync("/v1/auth/logout", new
        {
            refreshToken = refreshedA.RefreshToken,
        });
        Assert.Equal(HttpStatusCode.NoContent, logoutAResp.StatusCode);

        var refreshAfterLogoutA = await client.PostAsJsonAsync("/v1/auth/refresh", new
        {
            refreshToken = refreshedA.RefreshToken,
        });
        Assert.Equal(HttpStatusCode.Unauthorized, refreshAfterLogoutA.StatusCode);

        // Refresh de B sigue activo y no fue afectado por logout de A.
        var refreshBResp = await client.PostAsJsonAsync("/v1/auth/refresh", new
        {
            refreshToken = sessionB.RefreshToken,
        });
        Assert.Equal(HttpStatusCode.OK, refreshBResp.StatusCode);

        // 5. Token AdminClinica de A manipulando ID de B recibe 404 y no modifica B.
        var adminAPlus = await createStaff.ExecuteAsync(new CreateStaffCommand(
            IdentityStoreScope.ForTenant(MultiPostgresFixture.ClinicAId),
            adminAId,
            "Segundo Admin Alfa",
            "admin2.alfa@vital.demo",
            "AdminAlfa2#26",
            GenerateTemporaryPassword: false,
            "ADMIN_CLINICA",
            null,
            null,
            null,
            StaffPermissions.ForAdminClinica()));
        Assert.True(adminAPlus.IsSuccess);

        var adminALoginResp = await client.PostAsJsonAsync("/v1/auth/login", new
        {
            clinicSlug = MultiPostgresFixture.ClinicASlug,
            email = "admin2.alfa@vital.demo",
            password = "AdminAlfa2#26",
        });
        Assert.Equal(HttpStatusCode.OK, adminALoginResp.StatusCode);
        var adminASession = await adminALoginResp.Content.ReadFromJsonAsync<AuthSessionResult>();

        using (var crossTenantReq = new HttpRequestMessage(HttpMethod.Patch, $"/v1/staff/{createdB.Value.Account.Id}/status"))
        {
            crossTenantReq.Headers.Authorization = new AuthenticationHeaderValue("Bearer", adminASession!.AccessToken);
            crossTenantReq.Content = JsonContent.Create(new { active = false });
            var crossTenantResp = await client.SendAsync(crossTenantReq);
            Assert.Equal(HttpStatusCode.NotFound, crossTenantResp.StatusCode);
        }

        // 6. SuperAdmin autenticado únicamente en BD Global.
        var superLoginResp = await client.PostAsJsonAsync("/v1/auth/platform/login", new
        {
            email = "superadmin@vital.demo",
            password = MultiPostgresFixture.SuperAdminPassword,
        });
        Assert.Equal(HttpStatusCode.OK, superLoginResp.StatusCode);
        var superSession = await superLoginResp.Content.ReadFromJsonAsync<AuthSessionResult>();
        Assert.NotNull(superSession);
        Assert.Null(superSession!.Account.TenantId);

        using (var superMeReq = new HttpRequestMessage(HttpMethod.Get, "/v1/auth/me"))
        {
            superMeReq.Headers.Authorization = new AuthenticationHeaderValue("Bearer", superSession.AccessToken);
            var superMeResp = await client.SendAsync(superMeReq);
            Assert.Equal(HttpStatusCode.OK, superMeResp.StatusCode);
        }

        using (var superStaffReq = new HttpRequestMessage(HttpMethod.Get, "/v1/staff"))
        {
            superStaffReq.Headers.Authorization = new AuthenticationHeaderValue("Bearer", superSession.AccessToken);
            var superStaffResp = await client.SendAsync(superStaffReq);
            Assert.Equal(HttpStatusCode.Forbidden, superStaffResp.StatusCode);
        }

        // Un admin de clínica no puede autenticarse en /v1/auth/platform/login.
        var clinicAsPlatformResp = await client.PostAsJsonAsync("/v1/auth/platform/login", new
        {
            email = "admin2.alfa@vital.demo",
            password = "AdminAlfa2#26",
        });
        Assert.Equal(HttpStatusCode.Unauthorized, clinicAsPlatformResp.StatusCode);

        // 7. Verificación directa en PostgreSQL: aislamiento físico absoluto entre Global, Alfa y Beta.
        Assert.Equal(1L, await CountSqlAsync(fixture.GlobalDbConnectionString, "SELECT COUNT(*) FROM identity.accounts;"));
        Assert.Equal(0L, await CountSqlAsync(fixture.GlobalDbConnectionString, "SELECT COUNT(*) FROM identity.accounts WHERE tenant_id IS NOT NULL;"));
        Assert.Equal(0L, await CountSqlAsync(fixture.TenantADbConnectionString, $"SELECT COUNT(*) FROM identity.accounts WHERE tenant_id <> '{MultiPostgresFixture.ClinicAId}' OR role = 'SUPER_ADMIN';"));
        Assert.Equal(0L, await CountSqlAsync(fixture.TenantBDbConnectionString, $"SELECT COUNT(*) FROM identity.accounts WHERE tenant_id <> '{MultiPostgresFixture.ClinicBId}' OR role = 'SUPER_ADMIN';"));
        Assert.Equal(3L, await CountSqlAsync(fixture.TenantADbConnectionString, "SELECT COUNT(*) FROM identity.accounts;"));
        Assert.Equal(2L, await CountSqlAsync(fixture.TenantBDbConnectionString, "SELECT COUNT(*) FROM identity.accounts;"));
    }

    [Fact]
    public async Task ProvisionInitialClinicAdmin_RunsReproducibleMigrations_SurvivesRestarts_AndPreventsConcurrencyDuplicates()
    {
        // BD C vacía sin tablas inicialmente.
        Assert.Equal(0L, await CountSqlAsync(
            fixture.TenantNewDbConnectionString,
            "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = 'identity';"));

        var sameRequestId = $"prov-nueva-{Guid.NewGuid():N}";

        // Instancia 1: 8 llamadas concurrentes con el MISMO provisioning_request_id sobre BD nueva vacía.
        await using (var factory1 = fixture.CreateFactory())
        {
            var client1 = factory1.CreateDefaultClient();
            using var channel1 = GrpcChannel.ForAddress(
                client1.BaseAddress!,
                new GrpcChannelOptions { HttpClient = client1 });
            var grpc1 = new IdentityProvisioningService.IdentityProvisioningServiceClient(channel1);
            var headers = new Metadata { { "x-internal-service-key", MultiPostgresFixture.InternalGrpcKey } };

            var concurrentSameTasks = Enumerable.Range(0, 8)
                .Select(_ => grpc1.ProvisionInitialClinicAdminAsync(
                    new ProvisionInitialClinicAdminRequest
                    {
                        TenantId = MultiPostgresFixture.ClinicNewId.ToString(),
                        ProvisioningRequestId = sameRequestId,
                        ClinicSlug = MultiPostgresFixture.ClinicNewSlug,
                        ClinicName = "Clínica Nueva",
                        AdminFullName = "Mtro. Nuevo",
                        AdminEmail = "admin@nueva.vital.demo",
                    },
                    headers).ResponseAsync)
                .ToArray();

            var responses = await Task.WhenAll(concurrentSameTasks);
            var distinctAccountIds = responses.Select(r => r.InitialAdminAccountId).Distinct().ToList();
            Assert.Single(distinctAccountIds);
            Assert.All(responses, r => Assert.Equal(ProvisioningStatus.Ready, r.Status));
        }

        // Instancia 2 (simulando reinicio completo del proceso): mismo provisioning_request_id retorna idempotente mismo accountId.
        await using (var factory2 = fixture.CreateFactory())
        {
            var client2 = factory2.CreateDefaultClient();
            using var channel2 = GrpcChannel.ForAddress(
                client2.BaseAddress!,
                new GrpcChannelOptions { HttpClient = client2 });
            var grpc2 = new IdentityProvisioningService.IdentityProvisioningServiceClient(channel2);
            var headers = new Metadata { { "x-internal-service-key", MultiPostgresFixture.InternalGrpcKey } };

            var restartRetry = await grpc2.ProvisionInitialClinicAdminAsync(
                new ProvisionInitialClinicAdminRequest
                {
                    TenantId = MultiPostgresFixture.ClinicNewId.ToString(),
                    ProvisioningRequestId = sameRequestId,
                    ClinicSlug = MultiPostgresFixture.ClinicNewSlug,
                    ClinicName = "Clínica Nueva",
                    AdminFullName = "Mtro. Nuevo",
                    AdminEmail = "admin@nueva.vital.demo",
                },
                headers);

            Assert.Equal(ProvisioningStatus.Ready, restartRetry.Status);
            Assert.Equal(1L, await CountSqlAsync(fixture.TenantNewDbConnectionString, "SELECT COUNT(*) FROM identity.accounts;"));
            Assert.Equal(1L, await CountSqlAsync(fixture.TenantNewDbConnectionString, "SELECT COUNT(*) FROM identity.provisioning_records;"));

            // Clínica D (pendiente y vacía): 8 solicitudes simultáneas con DISTINTOS provisioning_request_id y correos.
            var raceTasks = Enumerable.Range(0, 8)
                .Select(i => CallProvisionAndCaptureAsync(
                    grpc2,
                    headers,
                    new ProvisionInitialClinicAdminRequest
                    {
                        TenantId = MultiPostgresFixture.ClinicRaceId.ToString(),
                        ProvisioningRequestId = $"prov-race-{i}-{Guid.NewGuid():N}",
                        ClinicSlug = MultiPostgresFixture.ClinicRaceSlug,
                        ClinicName = "Clínica Carrera",
                        AdminFullName = $"Admin Carrera {i}",
                        AdminEmail = $"admin{i}@carrera.vital.demo",
                    }))
                .ToArray();

            var raceOutcomes = await Task.WhenAll(raceTasks);
            Assert.Equal(1, raceOutcomes.Count(o => o.StatusCode == StatusCode.OK));
            Assert.Equal(7, raceOutcomes.Count(o => o.StatusCode == StatusCode.AlreadyExists));
            Assert.Equal(1L, await CountSqlAsync(fixture.TenantRaceDbConnectionString, "SELECT COUNT(*) FROM identity.accounts;"));
            Assert.Equal(1L, await CountSqlAsync(fixture.TenantRaceDbConnectionString, "SELECT COUNT(*) FROM identity.provisioning_records;"));
        }
    }

    [Fact]
    public async Task GrpcProvisioning_FailsClosed_WhenKeyMissingInvalidOrMisconfigured()
    {
        await using var factory = fixture.CreateFactory();
        var client = factory.CreateDefaultClient();
        using var channel = GrpcChannel.ForAddress(
            client.BaseAddress!,
            new GrpcChannelOptions { HttpClient = client });
        var grpcClient = new IdentityProvisioningService.IdentityProvisioningServiceClient(channel);

        var request = new ProvisionInitialClinicAdminRequest
        {
            TenantId = MultiPostgresFixture.ClinicNewId.ToString(),
            ProvisioningRequestId = "unauth-test",
            ClinicSlug = MultiPostgresFixture.ClinicNewSlug,
            ClinicName = "Clínica Nueva",
            AdminFullName = "Admin",
            AdminEmail = "unauth@nueva.vital.demo",
        };

        var missingHeaderEx = await Assert.ThrowsAsync<RpcException>(() =>
            grpcClient.ProvisionInitialClinicAdminAsync(request).ResponseAsync);
        Assert.Equal(StatusCode.Unauthenticated, missingHeaderEx.StatusCode);

        var wrongHeaderEx = await Assert.ThrowsAsync<RpcException>(() =>
            grpcClient.ProvisionInitialClinicAdminAsync(
                request,
                new Metadata { { "x-internal-service-key", "wrong-key-value" } }).ResponseAsync);
        Assert.Equal(StatusCode.Unauthenticated, wrongHeaderEx.StatusCode);

        // Si el servidor se instancia sin InternalGrpc:ApiKey válido, debe fallar cerrado incluso si el llamador envía cabecera.
        using var scope = factory.Services.CreateScope();
        var useCase = scope.ServiceProvider.GetRequiredService<ProvisionInitialClinicAdminUseCase>();
        var misconfiguredService = new IdentityProvisioningGrpcService(
            useCase,
            Options.Create(new InternalGrpcOptions { ApiKey = "" }),
            NullLogger<IdentityProvisioningGrpcService>.Instance);

        var failClosedEx = await Assert.ThrowsAsync<RpcException>(() =>
            misconfiguredService.ProvisionInitialClinicAdmin(
                request,
                new DummyServerCallContext(new Metadata { { "x-internal-service-key", "any" } })));
        Assert.Equal(StatusCode.Unauthenticated, failClosedEx.StatusCode);
    }

    private static async Task<(StatusCode StatusCode, ProvisionInitialClinicAdminResponse? Response)>
        CallProvisionAndCaptureAsync(
            IdentityProvisioningService.IdentityProvisioningServiceClient client,
            Metadata headers,
            ProvisionInitialClinicAdminRequest request)
    {
        try
        {
            var resp = await client.ProvisionInitialClinicAdminAsync(request, headers);
            return (StatusCode.OK, resp);
        }
        catch (RpcException ex)
        {
            return (ex.StatusCode, null);
        }
    }

    private static async Task<long> CountSqlAsync(string connectionString, string sql)
    {
        await using var conn = new NpgsqlConnection(connectionString);
        await conn.OpenAsync();
        await using var cmd = conn.CreateCommand();
        cmd.CommandText = sql;
        var scalar = await cmd.ExecuteScalarAsync();
        return Convert.ToInt64(scalar);
    }
}
