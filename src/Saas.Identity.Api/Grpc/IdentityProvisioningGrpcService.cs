using System.Security.Cryptography;
using System.Text;
using Grpc.Core;
using Microsoft.Extensions.Options;
using Saas.Contracts.PlatformIdentity.V1;
using Saas.Identity.Application.UseCases.Provisioning;
using DomainStatus = Saas.Identity.Domain.ValueObjects.ProvisioningRecordStatus;
using ProtoStatus = Saas.Contracts.PlatformIdentity.V1.ProvisioningStatus;

namespace Saas.Identity.Api.Grpc;

internal sealed class IdentityProvisioningGrpcService(
    ProvisionInitialClinicAdminUseCase useCase,
    IOptions<InternalGrpcOptions> optionsAccessor,
    ILogger<IdentityProvisioningGrpcService> logger)
    : IdentityProvisioningService.IdentityProvisioningServiceBase
{
    public override async Task<ProvisionInitialClinicAdminResponse> ProvisionInitialClinicAdmin(
        ProvisionInitialClinicAdminRequest request,
        ServerCallContext context)
    {
        var configuredKey = optionsAccessor.Value.ApiKey;
        if (!string.IsNullOrWhiteSpace(configuredKey))
        {
            var presentedKey = context.RequestHeaders.GetValue("x-internal-service-key");
            if (string.IsNullOrEmpty(presentedKey) || !FixedTimeEquals(configuredKey, presentedKey))
            {
                logger.LogWarning(
                    "Llamada gRPC no autenticada rechazada en ProvisionInitialClinicAdmin (RequestId={RequestId}).",
                    request.ProvisioningRequestId);
                throw new RpcException(new Status(
                    StatusCode.Unauthenticated,
                    "Credencial interna x-internal-service-key inválida o ausente."));
            }
        }

        if (!Guid.TryParse(request.TenantId, out var tenantId))
        {
            throw new RpcException(new Status(
                StatusCode.InvalidArgument,
                "El campo tenant_id debe tener formato UUID válido."));
        }

        var result = await useCase.ExecuteAsync(
            new ProvisionInitialClinicAdminCommand(
                tenantId,
                request.ProvisioningRequestId,
                request.ClinicSlug,
                request.ClinicName,
                request.AdminFullName,
                request.AdminEmail),
            context.CancellationToken);

        if (result.IsFailure)
        {
            var grpcCode = result.Error.Code switch
            {
                "VALIDATION_ERROR" => StatusCode.InvalidArgument,
                "PROVISIONING_CONFLICT" => StatusCode.FailedPrecondition,
                "INITIAL_ADMIN_ALREADY_EXISTS" or "DUPLICATE_STAFF_EMAIL" => StatusCode.AlreadyExists,
                "EMAIL_DELIVERY_FAILED" => StatusCode.Unavailable,
                _ => result.Error.HttpStatus == 503 ? StatusCode.Unavailable : StatusCode.Internal,
            };

            throw new RpcException(new Status(grpcCode, $"{result.Error.Code}: {result.Error.Message}"));
        }

        var value = result.Value;
        return new ProvisionInitialClinicAdminResponse
        {
            TenantId = value.TenantId.ToString(),
            ProvisioningRequestId = value.ProvisioningRequestId,
            InitialAdminAccountId = value.InitialAdminAccountId.ToString(),
            Status = MapStatus(value.Status),
            EvaluatedAtGmt6 = value.EvaluatedAtGmt6,
            TemporaryPasswordEmailSent = value.TemporaryPasswordEmailSent,
        };
    }

    private static ProtoStatus MapStatus(DomainStatus status) =>
        status switch
        {
            DomainStatus.PENDING_ACTIVATION => ProtoStatus.PendingActivation,
            DomainStatus.READY => ProtoStatus.Ready,
            DomainStatus.FAILED => ProtoStatus.Failed,
            _ => ProtoStatus.Unspecified,
        };

    private static bool FixedTimeEquals(string expected, string actual)
    {
        var expectedBytes = Encoding.UTF8.GetBytes(expected);
        var actualBytes = Encoding.UTF8.GetBytes(actual);
        return CryptographicOperations.FixedTimeEquals(expectedBytes, actualBytes);
    }
}
