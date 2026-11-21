using Grpc.Core;
using Microsoft.Extensions.Logging.Abstractions;
using Saas.Contracts.PlatformIdentity.V1;
using Saas.Identity.Application.Ports;
using Saas.Identity.Infrastructure.Email;
using Saas.Identity.Infrastructure.Platform;
using DomainState = Saas.Identity.Domain.ValueObjects.TenantOperationalState;
using ProtoState = Saas.Contracts.PlatformIdentity.V1.TenantOperationalState;

namespace Saas.Identity.UnitTests;

public sealed class GrpcAdaptersTests
{
    private sealed class FakeCallInvoker(
        Func<GetTenantAccessStateRequest, Metadata?, GetTenantAccessStateResponse> handler) : CallInvoker
    {
        public override AsyncUnaryCall<TResponse> AsyncUnaryCall<TRequest, TResponse>(
            Method<TRequest, TResponse> method,
            string? host,
            CallOptions options,
            TRequest request)
        {
            if (request is GetTenantAccessStateRequest accessRequest)
            {
                try
                {
                    var result = (TResponse)(object)handler(accessRequest, options.Headers);
                    return new AsyncUnaryCall<TResponse>(
                        Task.FromResult(result),
                        Task.FromResult(new Metadata()),
                        () => Status.DefaultSuccess,
                        () => new Metadata(),
                        () => { });
                }
                catch (RpcException rpcEx)
                {
                    return new AsyncUnaryCall<TResponse>(
                        Task.FromException<TResponse>(rpcEx),
                        Task.FromResult(new Metadata()),
                        () => rpcEx.Status,
                        () => new Metadata(),
                        () => { });
                }
            }

            throw new NotSupportedException();
        }

        public override TResponse BlockingUnaryCall<TRequest, TResponse>(
            Method<TRequest, TResponse> method,
            string? host,
            CallOptions options,
            TRequest request) =>
            throw new NotSupportedException();

        public override AsyncServerStreamingCall<TResponse> AsyncServerStreamingCall<TRequest, TResponse>(
            Method<TRequest, TResponse> method,
            string? host,
            CallOptions options,
            TRequest request) =>
            throw new NotSupportedException();

        public override AsyncClientStreamingCall<TRequest, TResponse> AsyncClientStreamingCall<TRequest, TResponse>(
            Method<TRequest, TResponse> method,
            string? host,
            CallOptions options) =>
            throw new NotSupportedException();

        public override AsyncDuplexStreamingCall<TRequest, TResponse> AsyncDuplexStreamingCall<TRequest, TResponse>(
            Method<TRequest, TResponse> method,
            string? host,
            CallOptions options) =>
            throw new NotSupportedException();
    }

    [Fact]
    public async Task GrpcTenantAccessStateAdapter_MapsActivaNotFoundAndFailClosedUnavailable()
    {
        var tenantId = Guid.Parse("10000000-0000-0000-0000-000000000001");
        Metadata? capturedHeaders = null;

        var invoker = new FakeCallInvoker((req, headers) =>
        {
            capturedHeaders = headers;
            if (req.LookupCase == GetTenantAccessStateRequest.LookupOneofCase.Slug &&
                req.Slug == "clinica-norte")
            {
                return new GetTenantAccessStateResponse
                {
                    TenantId = tenantId.ToString(),
                    Slug = "clinica-norte",
                    Name = "Clínica Médica del Norte",
                    State = ProtoState.Activa,
                    MayAuthenticate = true,
                    MaxActiveAccounts = 12,
                    EvaluatedAtGmt6 = "2026-11-21T13:00:00-06:00",
                };
            }

            if (req.LookupCase == GetTenantAccessStateRequest.LookupOneofCase.Slug &&
                req.Slug == "desconocida")
            {
                throw new RpcException(new Status(StatusCode.NotFound, "Tenant not found"));
            }

            throw new RpcException(new Status(StatusCode.Unavailable, "Platform unavailable"));
        });

        var client = new TenantAccessService.TenantAccessServiceClient(invoker);
        var options = Microsoft.Extensions.Options.Options.Create(new PlatformOptions
        {
            Mode = "Grpc",
            InternalServiceKey = "SecretKey123",
            TimeoutSeconds = 3,
        });

        var adapter = new GrpcTenantAccessStateAdapter(
            client,
            options,
            NullLogger<GrpcTenantAccessStateAdapter>.Instance);

        var found = await adapter.GetBySlugAsync("clinica-norte");
        Assert.False(found.PlatformUnavailable);
        Assert.NotNull(found.Tenant);
        Assert.Equal(tenantId, found.Tenant.TenantId);
        Assert.Equal(DomainState.ACTIVA, found.Tenant.State);
        Assert.True(found.Tenant.MayAuthenticate);
        Assert.Equal(12, found.Tenant.MaxActiveAccounts);
        Assert.Equal("SecretKey123", capturedHeaders?.GetValue("x-internal-service-key"));

        var notFound = await adapter.GetBySlugAsync("desconocida");
        Assert.False(notFound.PlatformUnavailable);
        Assert.Null(notFound.Tenant);

        var unavailable = await adapter.GetByTenantIdAsync(tenantId);
        Assert.True(unavailable.PlatformUnavailable);
        Assert.Null(unavailable.Tenant);
    }

    [Fact]
    public async Task SmtpTemporaryPasswordDeliveryAdapter_RespectsLogOnlyAndSimulateFailure()
    {
        var okAdapter = new SmtpTemporaryPasswordDeliveryAdapter(
            Microsoft.Extensions.Options.Options.Create(new EmailOptions { Mode = "LogOnly" }),
            NullLogger<SmtpTemporaryPasswordDeliveryAdapter>.Instance);

        var message = new TemporaryPasswordEmailMessage(
            "admin@aurora.vital.demo",
            "Mtro. Ernesto Cárdenas",
            "clinica-aurora",
            "Unidad Clínica Aurora",
            "TmpPass2026!",
            true);

        var okResult = await okAdapter.SendTemporaryPasswordAsync(message);
        Assert.True(okResult.Succeeded);

        var failAdapter = new SmtpTemporaryPasswordDeliveryAdapter(
            Microsoft.Extensions.Options.Options.Create(new EmailOptions { Mode = "LogOnly", SimulateFailure = true }),
            NullLogger<SmtpTemporaryPasswordDeliveryAdapter>.Instance);

        var failResult = await failAdapter.SendTemporaryPasswordAsync(message);
        Assert.False(failResult.Succeeded);
        Assert.Equal("EMAIL_DELIVERY_FAILED", failResult.ErrorCode);
    }
}
