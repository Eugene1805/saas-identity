namespace Saas.Identity.Domain.Entities;

public sealed class RefreshTokenSession
{
    private RefreshTokenSession()
    {
        TokenHash = string.Empty;
    }

    private RefreshTokenSession(
        Guid id,
        Guid accountId,
        Guid? tenantId,
        string tokenHash,
        DateTimeOffset expiresAtUtc,
        DateTimeOffset createdAtUtc)
    {
        Id = id;
        AccountId = accountId;
        TenantId = tenantId;
        TokenHash = tokenHash;
        ExpiresAtUtc = expiresAtUtc.ToUniversalTime();
        CreatedAtUtc = createdAtUtc.ToUniversalTime();
    }

    public Guid Id { get; private set; }
    public Guid AccountId { get; private set; }
    public Guid? TenantId { get; private set; }
    public string TokenHash { get; private set; }
    public DateTimeOffset ExpiresAtUtc { get; private set; }
    public DateTimeOffset CreatedAtUtc { get; private set; }
    public DateTimeOffset? RevokedAtUtc { get; private set; }
    public string? RevocationReason { get; private set; }
    public Guid? ReplacedByTokenId { get; private set; }

    public bool IsRevoked => RevokedAtUtc is not null;

    public bool IsExpired(DateTimeOffset utcNow) => ExpiresAtUtc <= utcNow;

    public bool IsActive(DateTimeOffset utcNow) => !IsRevoked && !IsExpired(utcNow);

    public static RefreshTokenSession Create(
        Guid id,
        Guid accountId,
        Guid? tenantId,
        string tokenHash,
        DateTimeOffset expiresAtUtc,
        DateTimeOffset createdAtUtc)
    {
        if (string.IsNullOrWhiteSpace(tokenHash))
        {
            throw new ArgumentException("El hash del refresh token es obligatorio.", nameof(tokenHash));
        }

        if (expiresAtUtc <= createdAtUtc)
        {
            throw new ArgumentException("La expiración del refresh token debe ser posterior a la creación.", nameof(expiresAtUtc));
        }

        return new RefreshTokenSession(id, accountId, tenantId, tokenHash, expiresAtUtc, createdAtUtc);
    }

    public void Revoke(DateTimeOffset utcNow, string reason, Guid? replacedByTokenId = null)
    {
        if (IsRevoked)
        {
            return;
        }

        RevokedAtUtc = utcNow.ToUniversalTime();
        RevocationReason = reason;
        ReplacedByTokenId = replacedByTokenId;
    }
}
