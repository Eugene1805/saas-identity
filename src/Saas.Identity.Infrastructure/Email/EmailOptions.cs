namespace Saas.Identity.Infrastructure.Email;

public sealed class EmailOptions
{
    public const string SectionName = "Email";

    public string Mode { get; init; } = "LogOnly";
    public string FromAddress { get; init; } = "no-reply@vital.demo";
    public string FromName { get; init; } = "Vital Identidad";
    public string SmtpHost { get; init; } = string.Empty;
    public int SmtpPort { get; init; } = 587;
    public bool EnableSsl { get; init; } = true;
    public string Username { get; init; } = string.Empty;
    public string Password { get; init; } = string.Empty;
    public bool SimulateFailure { get; init; }
}
