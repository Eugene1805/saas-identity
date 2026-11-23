namespace Saas.Identity.Application.Ports;

public sealed class TenantDatabaseUnavailableException : Exception
{
    public TenantDatabaseUnavailableException(
        Guid tenantId,
        string errorCode,
        string message,
        Exception? innerException = null)
        : base(message, innerException)
    {
        TenantId = tenantId;
        ErrorCode = errorCode;
    }

    public Guid TenantId { get; }
    public string ErrorCode { get; }
}
