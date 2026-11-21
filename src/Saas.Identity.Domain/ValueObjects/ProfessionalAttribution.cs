namespace Saas.Identity.Domain.ValueObjects;

public sealed record ProfessionalAttribution(
    string LicenseCode,
    string Title,
    string RegisteredAtGmt6);
