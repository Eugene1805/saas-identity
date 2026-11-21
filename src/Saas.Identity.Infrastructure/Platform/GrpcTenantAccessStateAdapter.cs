using Grpc.Core;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Saas.Contracts.PlatformIdentity.V1;
using Saas.Identity.Application.Ports;
using DomainState = Saas.Identity.Domain.ValueObjects.TenantOperationalState;
using ProtoState = Saas.Contracts.PlatformIdentity.V1.TenantOperationalState;

namespace Saas.Identity.Infrastructure.Platform;

public sealed class GrpcTenantAccessStateAdapter(
    TenantAccessService.TenantAccessServiceClient client,
    IOptions<PlatformOptions> optionsAccessor,
    ILogger<GrpcTenantAccessStateAdapter> logger) : ITenantAccessStatePort
{
    public Task<TenantLookupResult> GetBySlugAsync(
        string clinicSlug,
        CancellationToken cancellationToken = default)
    {
        var request = new GetTenantAccessStateRequest
        {
            Slug = clinicSlug.Trim().ToLowerInvariant(),
        };

        return QueryPlatformAsync(request, $"slug={request.Slug}", cancellationToken);
    }

    public Task<TenantLookupResult> GetByTenantIdAsync(
        Guid tenantId,
        CancellationToken cancellationToken = default)
    {
        var request = new GetTenantAccessStateRequest
        {
            TenantId = tenantId.ToString(),
        };

        return QueryPlatformAsync(request, $"tenantId={tenantId}", cancellationToken);
    }

    private async Task<TenantLookupResult> QueryPlatformAsync(
        GetTenantAccessStateRequest request,
        string lookupLabel,
        CancellationToken cancellationToken)
    {
        var opts = optionsAccessor.Value;
        if (opts.SimulateUnavailable)
        {
            return TenantLookupResult.Unavailable();
        }

        Metadata? headers = null;
        if (!string.IsNullOrWhiteSpace(opts.InternalServiceKey))
        {
            headers = new Metadata
            {
                { "x-internal-service-key", opts.InternalServiceKey },
            };
        }

        var deadline = DateTime.UtcNow.AddSeconds(Math.Max(1, opts.TimeoutSeconds));

        try
        {
            var response = await client.GetTenantAccessStateAsync(
                request,
                headers,
                deadline,
                cancellationToken).ResponseAsync;

            if (!Guid.TryParse(response.TenantId, out var parsedTenantId))
            {
                logger.LogWarning(
                    "Platform devolvió un tenant_id inválido ({TenantId}) para {Lookup}. Aplicando fallo cerrado.",
                    response.TenantId,
                    lookupLabel);
                return TenantLookupResult.Unavailable();
            }

            var mappedState = MapState(response.State);
            if (mappedState is null)
            {
                logger.LogWarning(
                    "Platform devolvió un estado operativo desconocido ({State}) para {Lookup}. Aplicando fallo cerrado.",
                    response.State,
                    lookupLabel);
                return TenantLookupResult.Unavailable();
            }

            return TenantLookupResult.Found(new Domain.ValueObjects.TenantAccessState(
                parsedTenantId,
                response.Slug,
                response.Name,
                mappedState.Value,
                response.MayAuthenticate,
                response.MaxActiveAccounts,
                response.EvaluatedAtGmt6));
        }
        catch (RpcException ex) when (ex.StatusCode == StatusCode.NotFound)
        {
            return TenantLookupResult.NotFound();
        }
        catch (RpcException ex)
        {
            logger.LogWarning(
                ex,
                "Fallo al consultar GetTenantAccessState en Platform ({Lookup}, gRPC StatusCode={StatusCode}). Aplicando fallo cerrado.",
                lookupLabel,
                ex.StatusCode);
            return TenantLookupResult.Unavailable();
        }
    }

    private static DomainState? MapState(ProtoState state) =>
        state switch
        {
            ProtoState.PendienteAdmin => DomainState.PENDIENTE_ADMIN,
            ProtoState.Activa => DomainState.ACTIVA,
            ProtoState.Suspendida => DomainState.SUSPENDIDA,
            _ => null,
        };
}
