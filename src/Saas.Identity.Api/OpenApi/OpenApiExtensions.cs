using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.OpenApi;
using Microsoft.OpenApi;
using Scalar.AspNetCore;

namespace Saas.Identity.Api.OpenApi;

internal static class OpenApiExtensions
{
    public static IServiceCollection AddIdentityOpenApi(this IServiceCollection services)
    {
        services.AddOpenApi("v1", options =>
        {
            options.AddDocumentTransformer<IdentityOpenApiDocumentTransformer>();
        });

        return services;
    }

    public static void MapIdentityOpenApi(this WebApplication app)
    {
        var openApiEnabled = app.Environment.IsDevelopment() ||
            app.Configuration.GetValue("OpenApi:Enabled", false);

        if (!openApiEnabled)
        {
            return;
        }

        app.MapOpenApi();
        app.MapScalarApiReference(options =>
        {
            options.WithTitle("Vital - saas-identity API v1");
        });
    }
}

internal sealed class IdentityOpenApiDocumentTransformer(
    IAuthenticationSchemeProvider authenticationSchemeProvider) : IOpenApiDocumentTransformer
{
    public async Task TransformAsync(
        OpenApiDocument document,
        OpenApiDocumentTransformerContext context,
        CancellationToken cancellationToken)
    {
        document.Info = new OpenApiInfo
        {
            Title = "Vital - saas-identity API",
            Version = "v1",
            Description = "Microservicio de identidad multitenant (CU-12, CU-13, CU-14, CU-17 A2, política de contraseñas, bloqueo exponencial y horario GMT-6).",
        };

        var schemes = await authenticationSchemeProvider.GetAllSchemesAsync();
        if (!schemes.Any(s => string.Equals(s.Name, "Bearer", StringComparison.OrdinalIgnoreCase)))
        {
            return;
        }

        document.Components ??= new OpenApiComponents();
        document.Components.SecuritySchemes ??= new Dictionary<string, IOpenApiSecurityScheme>(StringComparer.Ordinal);
        document.Components.SecuritySchemes["Bearer"] = new OpenApiSecurityScheme
        {
            Type = SecuritySchemeType.Http,
            Scheme = "bearer",
            BearerFormat = "JWT",
            In = ParameterLocation.Header,
            Description = "Access Token JWT devuelto por /v1/auth/login, /v1/auth/platform/login o /v1/auth/refresh.",
        };

        var requirement = new OpenApiSecurityRequirement
        {
            [new OpenApiSecuritySchemeReference("Bearer", document)] = [],
        };

        foreach (var (pathKey, pathItem) in document.Paths)
        {
            if (pathItem.Operations is null)
            {
                continue;
            }

            var isProtected = string.Equals(pathKey, "/v1/auth/me", StringComparison.Ordinal) ||
                string.Equals(pathKey, "/v1/auth/change-password", StringComparison.Ordinal) ||
                pathKey.StartsWith("/v1/staff", StringComparison.Ordinal);

            if (!isProtected)
            {
                continue;
            }

            foreach (var operation in pathItem.Operations.Values)
            {
                operation.Security ??= [];
                operation.Security.Add(requirement);
            }
        }
    }
}
