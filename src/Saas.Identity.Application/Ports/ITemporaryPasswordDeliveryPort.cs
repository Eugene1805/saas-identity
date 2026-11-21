namespace Saas.Identity.Application.Ports;

public sealed record TemporaryPasswordEmailMessage(
    string RecipientEmail,
    string RecipientName,
    string ClinicSlug,
    string ClinicName,
    string TemporaryPassword,
    bool IsInitialClinicAdmin);

public sealed record EmailDeliveryResult(bool Succeeded, string? ErrorCode = null);

public interface ITemporaryPasswordDeliveryPort
{
    Task<EmailDeliveryResult> SendTemporaryPasswordAsync(
        TemporaryPasswordEmailMessage message,
        CancellationToken cancellationToken = default);
}
