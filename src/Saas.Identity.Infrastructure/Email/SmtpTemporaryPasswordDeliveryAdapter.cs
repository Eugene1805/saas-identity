using System.Net;
using System.Net.Mail;
using System.Text;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Saas.Identity.Application.Ports;

namespace Saas.Identity.Infrastructure.Email;

public sealed class SmtpTemporaryPasswordDeliveryAdapter(
    IOptions<EmailOptions> optionsAccessor,
    ILogger<SmtpTemporaryPasswordDeliveryAdapter> logger) : ITemporaryPasswordDeliveryPort
{
    public async Task<EmailDeliveryResult> SendTemporaryPasswordAsync(
        TemporaryPasswordEmailMessage message,
        CancellationToken cancellationToken = default)
    {
        var opts = optionsAccessor.Value;

        if (opts.SimulateFailure)
        {
            logger.LogWarning(
                "[Email] Fallo simulado al enviar contraseña temporal a {RecipientEmail} (clínica {ClinicSlug}).",
                message.RecipientEmail,
                message.ClinicSlug);
            return new EmailDeliveryResult(false, "EMAIL_DELIVERY_FAILED");
        }

        if (!string.Equals(opts.Mode, "Smtp", StringComparison.OrdinalIgnoreCase))
        {
            logger.LogInformation(
                "[Email:LogOnly] Correo de contraseña temporal despachado a {RecipientEmail} para clínica {ClinicSlug} (AdminInicial={IsInitialAdmin}).",
                message.RecipientEmail,
                message.ClinicSlug,
                message.IsInitialClinicAdmin);
            return new EmailDeliveryResult(true);
        }

        if (string.IsNullOrWhiteSpace(opts.SmtpHost))
        {
            logger.LogError(
                "[Email:Smtp] Email:SmtpHost no está configurado para entregar la contraseña temporal a {RecipientEmail}.",
                message.RecipientEmail);
            return new EmailDeliveryResult(false, "EMAIL_DELIVERY_FAILED");
        }

        try
        {
            using var mail = new MailMessage
            {
                From = new MailAddress(opts.FromAddress, opts.FromName, Encoding.UTF8),
                Subject = message.IsInitialClinicAdmin
                    ? $"[Vital] Habilitación inicial de AdminClinica - {message.ClinicName}"
                    : $"[Vital] Credencial temporal de acceso - {message.ClinicName}",
                Body = BuildEmailBody(message),
                BodyEncoding = Encoding.UTF8,
                SubjectEncoding = Encoding.UTF8,
                IsBodyHtml = false,
            };
            mail.To.Add(new MailAddress(message.RecipientEmail, message.RecipientName, Encoding.UTF8));

            using var client = new SmtpClient(opts.SmtpHost, opts.SmtpPort)
            {
                EnableSsl = opts.EnableSsl,
            };

            if (!string.IsNullOrWhiteSpace(opts.Username))
            {
                client.Credentials = new NetworkCredential(opts.Username, opts.Password);
            }

            await client.SendMailAsync(mail, cancellationToken);
            logger.LogInformation(
                "[Email:Smtp] Contraseña temporal enviada correctamente a {RecipientEmail} para clínica {ClinicSlug}.",
                message.RecipientEmail,
                message.ClinicSlug);
            return new EmailDeliveryResult(true);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            logger.LogWarning(
                ex,
                "[Email:Smtp] Error al enviar contraseña temporal a {RecipientEmail} para clínica {ClinicSlug}.",
                message.RecipientEmail,
                message.ClinicSlug);
            return new EmailDeliveryResult(false, "EMAIL_DELIVERY_FAILED");
        }
    }

    private static string BuildEmailBody(TemporaryPasswordEmailMessage message)
    {
        var roleLabel = message.IsInitialClinicAdmin
            ? "Administrador inicial de clínica (AdminClinica)"
            : "Personal autorizado";

        return $"""
            Hola {message.RecipientName},

            Se habilitó tu acceso en Vital como {roleLabel} para la clínica "{message.ClinicName}".

            Identificador de clínica (slug): {message.ClinicSlug}
            Correo institucional: {message.RecipientEmail}
            Contraseña temporal (uso inicial): {message.TemporaryPassword}

            Al iniciar sesión por primera vez deberás actualizar tu contraseña (8 a 40 caracteres con al menos una letra, un número y un símbolo).
            """;
    }
}
