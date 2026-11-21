using System.IdentityModel.Tokens.Jwt;
using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.IdentityModel.Tokens;
using Npgsql;
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

var jwtOptions = builder.Configuration.GetSection(JwtOptions.SectionName).Get<JwtOptions>() ?? new JwtOptions();
if (string.IsNullOrWhiteSpace(jwtOptions.SigningKey) ||
    Encoding.UTF8.GetByteCount(jwtOptions.SigningKey) < 32)
{
    throw new InvalidOperationException("Configura Jwt:SigningKey con al menos 32 bytes antes de iniciar saas-identity.");
}

JwtSecurityTokenHandler.DefaultMapInboundClaims = false;

builder.Services
    .AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.MapInboundClaims = false;
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidIssuer = jwtOptions.Issuer,
            ValidateAudience = true,
            ValidAudience = jwtOptions.Audience,
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtOptions.SigningKey)),
            ValidateLifetime = true,
            ClockSkew = TimeSpan.FromSeconds(30),
            RoleClaimType = "role",
        };
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

await InitializeDatabaseWithRetryAsync(app.Services, app.Logger);

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

static async Task InitializeDatabaseWithRetryAsync(IServiceProvider services, ILogger logger)
{
    const int maxAttempts = 10;
    for (var attempt = 1; attempt <= maxAttempts; attempt++)
    {
        try
        {
            using var scope = services.CreateScope();
            var initializer = scope.ServiceProvider.GetRequiredService<IdentityDbInitializer>();
            await initializer.InitializeAsync();
            return;
        }
        catch (Exception ex) when (ex is NpgsqlException or TimeoutException or InvalidOperationException && attempt < maxAttempts)
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
