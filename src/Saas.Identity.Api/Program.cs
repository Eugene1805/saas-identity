using System.IdentityModel.Tokens.Jwt;
using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Saas.Identity.Api.Endpoints;
using Saas.Identity.Api.Grpc;
using Saas.Identity.Api.OpenApi;
using Saas.Identity.Infrastructure;
using Saas.Identity.Infrastructure.Persistence;
using Saas.Identity.Infrastructure.Security;

var builder = WebApplication.CreateBuilder(args);

var httpPort = builder.Configuration.GetValue("Ports:Http", 8080);
var grpcPort = builder.Configuration.GetValue("Ports:Grpc", 8082);
builder.WebHost.ConfigureKestrel(options =>
{
    options.ListenAnyIP(httpPort, listen => listen.Protocols = HttpProtocols.Http1);
    options.ListenAnyIP(grpcPort, listen => listen.Protocols = HttpProtocols.Http2);
});

builder.Services.AddIdentityInfrastructure(builder.Configuration);
builder.Services.Configure<InternalGrpcOptions>(
    builder.Configuration.GetSection(InternalGrpcOptions.SectionName));
builder.Services.AddGrpc();
builder.Services.AddGrpcReflection();

var internalGrpcOptions = builder.Configuration.GetSection(InternalGrpcOptions.SectionName).Get<InternalGrpcOptions>() ?? new InternalGrpcOptions();
if (string.IsNullOrWhiteSpace(internalGrpcOptions.ApiKey) ||
    Encoding.UTF8.GetByteCount(internalGrpcOptions.ApiKey) < 16)
{
    throw new InvalidOperationException("Configura InternalGrpc:ApiKey con al menos 16 bytes antes de iniciar saas-identity.");
}

JwtSecurityTokenHandler.DefaultMapInboundClaims = false;

builder.Services
    .AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer();

builder.Services
    .AddOptions<JwtBearerOptions>(JwtBearerDefaults.AuthenticationScheme)
    .Configure<JwtCryptoMaterial>((options, cryptoMaterial) =>
    {
        options.MapInboundClaims = false;
        options.TokenValidationParameters = cryptoMaterial.CreateTokenValidationParameters();
    });

builder.Services.AddAuthorization();
builder.Services.AddProblemDetails();

var allowedOrigins = builder.Configuration.GetSection("Cors:AllowedOrigins").Get<string[]>()
    ?? ["http://localhost:5173", "http://127.0.0.1:5173", "http://localhost:4173"];

builder.Services.AddCors(options =>
{
    options.AddPolicy("VitalFrontend", policy =>
    {
        policy.WithOrigins(allowedOrigins)
            .AllowAnyHeader()
            .AllowAnyMethod();
    });
});

builder.Services.AddIdentityOpenApi();

var app = builder.Build();

await InitializeDatabaseWithRetryAsync(app.Services, app.Environment.IsProduction(), app.Logger);

app.UseExceptionHandler();
app.UseCors("VitalFrontend");
app.UseAuthentication();
app.UseAuthorization();

app.MapIdentityOpenApi();
app.MapHealthEndpoints();
app.MapAuthEndpoints();
app.MapStaffEndpoints();
app.MapGrpcService<IdentityProvisioningGrpcService>();
if (app.Environment.IsDevelopment() || app.Configuration.GetValue("OpenApi:Enabled", false))
{
    app.MapGrpcReflectionService();
}

app.Run();

static async Task InitializeDatabaseWithRetryAsync(
    IServiceProvider services,
    bool isProduction,
    ILogger logger)
{
    const int maxAttempts = 10;
    for (var attempt = 1; attempt <= maxAttempts; attempt++)
    {
        try
        {
            using var scope = services.CreateScope();
            var initializer = scope.ServiceProvider.GetRequiredService<IdentityDbInitializer>();
            await initializer.InitializeGlobalAsync(isProduction);
            await initializer.InitializeConfiguredDemoTenantsAsync(isProduction);
            return;
        }
        catch (Exception ex) when (ex is not OperationCanceledException && attempt < maxAttempts)
        {
            logger.LogWarning(
                ex,
                "Base de datos aún no disponible al inicializar Identity (intento {Attempt}/{MaxAttempts}).",
                attempt,
                maxAttempts);
            await Task.Delay(TimeSpan.FromSeconds(2));
        }
    }
}

public partial class Program;
