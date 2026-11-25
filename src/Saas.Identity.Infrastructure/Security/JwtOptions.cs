namespace Saas.Identity.Infrastructure.Security;

public sealed class JwtOptions
{
    public const string SectionName = "Jwt";

    public string Issuer { get; init; } = "saas-identity";
    public string Audience { get; init; } = "vital-saas";
    public string PrivateKeyPem { get; init; } = string.Empty;
    public string PrivateKeyPemPath { get; init; } = string.Empty;
    public string PublicKeyPem { get; init; } = string.Empty;
    public string PublicKeyPemPath { get; init; } = string.Empty;
    public string KeyId { get; init; } = string.Empty;
    public string RefreshTokenHmacKey { get; init; } = string.Empty;
    public int AccessTokenMinutes { get; init; } = 15;
    public int RefreshTokenDays { get; init; } = 7;
}
