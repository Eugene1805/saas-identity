using System.Security.Claims;
using Microsoft.AspNetCore.Mvc;
using Saas.Identity.Application.UseCases.Staff;
using Saas.Identity.Domain.ValueObjects;

namespace Saas.Identity.Api.Endpoints;

public sealed record CreateStaffHttpRequest(
    string FullName,
    string Email,
    string? Password,
    bool GenerateTemporaryPassword,
    string Role,
    string? Specialty,
    string? LicenseCode,
    string? Title,
    StaffPermissions Permissions);

public sealed record UpdateStaffRoleHttpRequest(
    string Role,
    string? Specialty,
    string? LicenseCode,
    string? Title,
    bool CanPrescribe,
    bool CanRegisterPatients,
    bool CanAssignInitialPrimary,
    bool CanUploadStudies,
    string? Note);

public sealed record UpdateStaffStatusHttpRequest(
    bool Active);

public sealed record UpdateAuxiliaryLinksHttpRequest(
    IReadOnlyList<Guid> SpecialistIds);

internal static class StaffEndpoints
{
    public static void MapStaffEndpoints(this IEndpointRouteBuilder endpoints)
    {
        var group = endpoints.MapGroup("/v1/staff")
            .WithTags("Staff")
            .RequireAuthorization();

        group.MapGet("/", async (
                ClaimsPrincipal user,
                ListTenantStaffUseCase useCase,
                HttpContext httpContext,
                CancellationToken cancellationToken) =>
            {
                if (!user.TryGetAccountId(out var actorAccountId))
                {
                    return Results.Unauthorized();
                }

                var result = await useCase.ExecuteAsync(actorAccountId, cancellationToken);
                return result.IsSuccess
                    ? Results.Ok(result.Value)
                    : ProblemDetailsMapper.ToProblem(result.Error, httpContext);
            })
            .WithName("ListTenantStaff")
            .WithSummary("Listar directorio de personal y cuota de la clínica (CU-12 / CU-17 A2)")
            .WithDescription("Devuelve cuentas del tenant autenticado con su ocupación actual frente al límite maxActiveAccounts e historial de auditoría de roles.")
            .Produces<TenantStaffDirectoryResult>(StatusCodes.Status200OK)
            .Produces(StatusCodes.Status401Unauthorized)
            .Produces<ProblemDetails>(StatusCodes.Status403Forbidden)
            .Produces<ProblemDetails>(StatusCodes.Status503ServiceUnavailable);

        group.MapPost("/", async (
                ClaimsPrincipal user,
                CreateStaffHttpRequest request,
                CreateStaffUseCase useCase,
                HttpContext httpContext,
                CancellationToken cancellationToken) =>
            {
                if (!user.TryGetAccountId(out var actorAccountId))
                {
                    return Results.Unauthorized();
                }

                var result = await useCase.ExecuteAsync(
                    new CreateStaffCommand(
                        actorAccountId,
                        request.FullName,
                        request.Email,
                        request.Password,
                        request.GenerateTemporaryPassword,
                        request.Role,
                        request.Specialty,
                        request.LicenseCode,
                        request.Title,
                        request.Permissions ?? StaffPermissions.None),
                    cancellationToken);

                return result.IsSuccess
                    ? Results.Created($"/v1/staff/{result.Value.Account.Id}", result.Value)
                    : ProblemDetailsMapper.ToProblem(result.Error, httpContext);
            })
            .WithName("CreateStaff")
            .WithSummary("Dar de alta un integrante de personal dentro de la clínica (CU-12 / CU-14 / CU-17 A2)")
            .WithDescription("Valida cuota máxima, bloquea escalación a SUPER_ADMIN, exige atribución profesional para prescribir y genera contraseña temporal opcional en Identity.")
            .Produces<CreateStaffResult>(StatusCodes.Status201Created)
            .Produces<ProblemDetails>(StatusCodes.Status400BadRequest)
            .Produces(StatusCodes.Status401Unauthorized)
            .Produces<ProblemDetails>(StatusCodes.Status403Forbidden)
            .Produces<ProblemDetails>(StatusCodes.Status409Conflict)
            .Produces<ProblemDetails>(StatusCodes.Status503ServiceUnavailable);

        group.MapPut("/{accountId:guid}/role", async (
                Guid accountId,
                ClaimsPrincipal user,
                UpdateStaffRoleHttpRequest request,
                UpdateStaffRoleUseCase useCase,
                HttpContext httpContext,
                CancellationToken cancellationToken) =>
            {
                if (!user.TryGetAccountId(out var actorAccountId))
                {
                    return Results.Unauthorized();
                }

                var result = await useCase.ExecuteAsync(
                    new UpdateStaffRoleCommand(
                        actorAccountId,
                        accountId,
                        request.Role,
                        request.Specialty,
                        request.LicenseCode,
                        request.Title,
                        request.CanPrescribe,
                        request.CanRegisterPatients,
                        request.CanAssignInitialPrimary,
                        request.CanUploadStudies,
                        request.Note),
                    cancellationToken);

                return result.IsSuccess
                    ? Results.Ok(result.Value)
                    : ProblemDetailsMapper.ToProblem(result.Error, httpContext);
            })
            .WithName("UpdateStaffRole")
            .WithSummary("Actualizar rol predefinido y facultades con auditoría GMT-6 (CU-14)")
            .WithDescription("Modifica el rol cerrado, atribución profesional y facultades registrando un evento inmutable de auditoría.")
            .Produces<StaffMemberDto>(StatusCodes.Status200OK)
            .Produces<ProblemDetails>(StatusCodes.Status400BadRequest)
            .Produces(StatusCodes.Status401Unauthorized)
            .Produces<ProblemDetails>(StatusCodes.Status403Forbidden)
            .Produces<ProblemDetails>(StatusCodes.Status404NotFound)
            .Produces<ProblemDetails>(StatusCodes.Status409Conflict)
            .Produces<ProblemDetails>(StatusCodes.Status503ServiceUnavailable);

        group.MapPatch("/{accountId:guid}/status", async (
                Guid accountId,
                ClaimsPrincipal user,
                UpdateStaffStatusHttpRequest request,
                UpdateStaffStatusUseCase useCase,
                HttpContext httpContext,
                CancellationToken cancellationToken) =>
            {
                if (!user.TryGetAccountId(out var actorAccountId))
                {
                    return Results.Unauthorized();
                }

                var result = await useCase.ExecuteAsync(
                    new UpdateStaffStatusCommand(actorAccountId, accountId, request.Active),
                    cancellationToken);

                return result.IsSuccess
                    ? Results.Ok(result.Value)
                    : ProblemDetailsMapper.ToProblem(result.Error, httpContext);
            })
            .WithName("UpdateStaffStatus")
            .WithSummary("Desactivar o reactivar una cuenta de personal (CU-12 / CU-17 A2)")
            .WithDescription("Protege al último AdminClinica activo, revoca refresh tokens al desactivar y valida cuota al reactivar.")
            .Produces<StaffMemberDto>(StatusCodes.Status200OK)
            .Produces(StatusCodes.Status401Unauthorized)
            .Produces<ProblemDetails>(StatusCodes.Status403Forbidden)
            .Produces<ProblemDetails>(StatusCodes.Status404NotFound)
            .Produces<ProblemDetails>(StatusCodes.Status409Conflict)
            .Produces<ProblemDetails>(StatusCodes.Status503ServiceUnavailable);

        group.MapPut("/{accountId:guid}/links", async (
                Guid accountId,
                ClaimsPrincipal user,
                UpdateAuxiliaryLinksHttpRequest request,
                UpdateAuxiliaryLinksUseCase useCase,
                HttpContext httpContext,
                CancellationToken cancellationToken) =>
            {
                if (!user.TryGetAccountId(out var actorAccountId))
                {
                    return Results.Unauthorized();
                }

                var result = await useCase.ExecuteAsync(
                    new UpdateAuxiliaryLinksCommand(
                        actorAccountId,
                        accountId,
                        request.SpecialistIds ?? []),
                    cancellationToken);

                return result.IsSuccess
                    ? Results.Ok(result.Value)
                    : ProblemDetailsMapper.ToProblem(result.Error, httpContext);
            })
            .WithName("UpdateAuxiliaryLinks")
            .WithSummary("Actualizar especialistas vinculados a un auxiliar (CU-12)")
            .WithDescription("Asigna únicamente cuentas Especialista activas dentro de la misma clínica al personal con rol AUXILIAR.")
            .Produces<StaffMemberDto>(StatusCodes.Status200OK)
            .Produces<ProblemDetails>(StatusCodes.Status400BadRequest)
            .Produces(StatusCodes.Status401Unauthorized)
            .Produces<ProblemDetails>(StatusCodes.Status403Forbidden)
            .Produces<ProblemDetails>(StatusCodes.Status404NotFound)
            .Produces<ProblemDetails>(StatusCodes.Status503ServiceUnavailable);
    }
}
