namespace Saas.Identity.Api.Grpc;

internal sealed class InternalGrpcOptions
{
    public const string SectionName = "InternalGrpc";

    public string ApiKey { get; init; } = string.Empty;
}
