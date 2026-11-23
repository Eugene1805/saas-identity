using System.Security.Claims;
using Microsoft.AspNetCore.Mvc;
using Saas.Identity.Application.UseCases.Auth;

namespace Saas.Identity.Api.Endpoints;

public sealed record LoginClinicHttpRequest(
    string ClinicSlug,
    string Email,
    string Password);

public sealed record LoginPlatformHttpRequest(
    string Email,
    string Password);

public sealed record RefreshHttpRequest(
    string RefreshToken);

public sealed record LogoutHttpRequest(
    string RefreshToken);

public sealed record ChangePasswordHttpRequest(
    string CurrentPassword,
    string NewPassword);

internal static class AuthEndpoints
{
    public static void MapAuthEndpoints(this IEndpointRouteBuilder endpoints)
    {
        var group = endpoints.MapGroup("/v1/auth")
            .WithTags("Auth");

        group.MapPost("/login", async (
                LoginClinicHttpRequest request,
                LoginClinicUseCase useCase,
                HttpContext httpContext,
                CancellationToken cancellationToken) =>
            {
                var result = await useCase.ExecuteAsync(
                    new LoginClinicCommand(request.ClinicSlug, request.Email, request.Password),
                    cancellationToken);

                return result.IsSuccess
                    ? Results.Ok(result.Value)
                    : ProblemDetailsMapper.ToProblem(result.Error, httpContext);
            })
            .WithName("LoginClinic")
            .WithSummary("Iniciar sesión en una clínica por slug (CU-13)")
            .WithDescription("Autentica personal operativo de una clínica aislada por tenantId y verifica clínica ACTIVA y bloqueo exponencial.")
            .AllowAnonymous()
            .Produces<AuthSessionResult>(StatusCodes.Status200OK)
            .Produces<ProblemDetails>(StatusCodes.Status400BadRequest)
            .Produces<ProblemDetails>(StatusCodes.Status401Unauthorized)
            .Produces<ProblemDetails>(StatusCodes.Status403Forbidden)
            .Produces<ProblemDetails>(StatusCodes.Status404NotFound)
            .Produces<ProblemDetails>(StatusCodes.Status429TooManyRequests)
            .Produces<ProblemDetails>(StatusCodes.Status503ServiceUnavailable);

        group.MapPost("/platform/login", async (
                LoginPlatformHttpRequest request,
                LoginPlatformUseCase useCase,
                HttpContext httpContext,
                CancellationToken cancellationToken) =>
            {
                var result = await useCase.ExecuteAsync(
                    new LoginPlatformCommand(request.Email, request.Password),
                    cancellationToken);

                return result.IsSuccess
                    ? Results.Ok(result.Value)
                    : ProblemDetailsMapper.ToProblem(result.Error, httpContext);
            })
            .WithName("LoginPlatform")
            .WithSummary("Iniciar sesión de SuperAdmin en plataforma SaaS (CU-13)")
            .WithDescription("Autentica operadores globales de plataforma (tenant_id nulo) sin mezclar identidades de clínicas.")
            .AllowAnonymous()
            .Produces<AuthSessionResult>(StatusCodes.Status200OK)
            .Produces<ProblemDetails>(StatusCodes.Status400BadRequest)
            .Produces<ProblemDetails>(StatusCodes.Status401Unauthorized)
            .Produces<ProblemDetails>(StatusCodes.Status403Forbidden)
            .Produces<ProblemDetails>(StatusCodes.Status429TooManyRequests);

        group.MapPost("/refresh", async (
                RefreshHttpRequest request,
                RefreshSessionUseCase useCase,
                HttpContext httpContext,
                CancellationToken cancellationToken) =>
            {
                var result = await useCase.ExecuteAsync(
                    new RefreshSessionCommand(request.RefreshToken),
                    cancellationToken);

                return result.IsSuccess
                    ? Results.Ok(result.Value)
                    : ProblemDetailsMapper.ToProblem(result.Error, httpContext);
            })
            .WithName("RefreshSession")
            .WithSummary("Rotar refresh token y renovar Access Token JWT")
            .WithDescription("Valida el refresh token persistido en PostgreSQL, detecta reutilización, revalida estado de la clínica/cuenta y rota la sesión.")
            .AllowAnonymous()
            .Produces<AuthSessionResult>(StatusCodes.Status200OK)
            .Produces<ProblemDetails>(StatusCodes.Status400BadRequest)
            .Produces<ProblemDetails>(StatusCodes.Status401Unauthorized)
            .Produces<ProblemDetails>(StatusCodes.Status403Forbidden)
            .Produces<ProblemDetails>(StatusCodes.Status503ServiceUnavailable);

        group.MapPost("/logout", async (
                LogoutHttpRequest request,
                LogoutUseCase useCase,
                HttpContext httpContext,
                CancellationToken cancellationToken) =>
            {
                var result = await useCase.ExecuteAsync(
                    new LogoutCommand(request.RefreshToken),
                    cancellationToken);

                return result.IsSuccess
                    ? Results.NoContent()
                    : ProblemDetailsMapper.ToProblem(result.Error, httpContext);
            })
            .WithName("LogoutSession")
            .WithSummary("Cerrar sesión revocando el refresh token en PostgreSQL")
            .WithDescription("Marca la sesión como revocada de manera idempotente para impedir futuras renovaciones.")
            .AllowAnonymous()
            .Produces(StatusCodes.Status204NoContent)
            .Produces<ProblemDetails>(StatusCodes.Status400BadRequest)
            .Produces<ProblemDetails>(StatusCodes.Status503ServiceUnavailable);

        group.MapPost("/change-password", async (
                ClaimsPrincipal user,
                ChangePasswordHttpRequest request,
                ChangePasswordUseCase useCase,
                HttpContext httpContext,
                CancellationToken cancellationToken) =>
            {
                if (!user.TryGetActorIdentity(out var actor))
                {
                    return Results.Unauthorized();
                }

                var result = await useCase.ExecuteAsync(
                    new ChangePasswordCommand(actor.StoreScope, actor.AccountId, request.CurrentPassword, request.NewPassword),
                    cancellationToken);

                return result.IsSuccess
                    ? Results.NoContent()
                    : ProblemDetailsMapper.ToProblem(result.Error, httpContext);
            })
            .WithName("ChangePassword")
            .WithSummary("Cambiar contraseña de la cuenta autenticada")
            .WithDescription("Valida la contraseña actual, aplica política 8-40 caracteres (letra, número y símbolo) y limpia el indicador de contraseña temporal.")
            .RequireAuthorization()
            .Produces(StatusCodes.Status204NoContent)
            .Produces<ProblemDetails>(StatusCodes.Status400BadRequest)
            .Produces<ProblemDetails>(StatusCodes.Status401Unauthorized)
            .Produces<ProblemDetails>(StatusCodes.Status403Forbidden)
            .Produces<ProblemDetails>(StatusCodes.Status503ServiceUnavailable);

        group.MapGet("/me", async (
                ClaimsPrincipal user,
                GetCurrentAccountUseCase useCase,
                HttpContext httpContext,
                CancellationToken cancellationToken) =>
            {
                if (!user.TryGetActorIdentity(out var actor))
                {
                    return Results.Unauthorized();
                }

                var result = await useCase.ExecuteAsync(actor.StoreScope, actor.AccountId, cancellationToken);
                return result.IsSuccess
                    ? Results.Ok(result.Value)
                    : ProblemDetailsMapper.ToProblem(result.Error, httpContext);
            })
            .WithName("GetCurrentAccount")
            .WithSummary("Consultar perfil de la cuenta autenticada vigente")
            .WithDescription("Valida el Access Token JWT Bearer y reconfirma vigencia de cuenta y clínica.")
            .RequireAuthorization()
            .Produces<AccountProfileDto>(StatusCodes.Status200OK)
            .Produces(StatusCodes.Status401Unauthorized)
            .Produces<ProblemDetails>(StatusCodes.Status403Forbidden)
            .Produces<ProblemDetails>(StatusCodes.Status503ServiceUnavailable);
    }
}
