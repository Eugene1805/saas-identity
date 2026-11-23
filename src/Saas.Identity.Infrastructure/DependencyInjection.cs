using Grpc.Net.Client;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Saas.Contracts.PlatformIdentity.V1;
using Saas.Identity.Application.Ports;
using Saas.Identity.Application.UseCases.Auth;
using Saas.Identity.Application.UseCases.Provisioning;
using Saas.Identity.Application.UseCases.Staff;
using Saas.Identity.Infrastructure.Email;
using Saas.Identity.Infrastructure.Persistence;
using Saas.Identity.Infrastructure.Persistence.Repositories;
using Saas.Identity.Infrastructure.Persistence.Tenancy;
using Saas.Identity.Infrastructure.Platform;
using Saas.Identity.Infrastructure.Security;

namespace Saas.Identity.Infrastructure;

public static class DependencyInjection
{
    public static IServiceCollection AddIdentityInfrastructure(
        this IServiceCollection services,
        IConfiguration configuration)
    {
        var globalConnectionString = configuration.GetConnectionString("IdentityGlobalDb")
            ?? configuration.GetConnectionString("IdentityDb");
        if (string.IsNullOrWhiteSpace(globalConnectionString))
        {
            throw new InvalidOperationException("Falta ConnectionStrings:IdentityGlobalDb.");
        }

        services.AddDbContextFactory<GlobalIdentityDbContext>(options =>
            options.UseNpgsql(
                globalConnectionString,
                npgsql => npgsql
                    .MigrationsHistoryTable("__EFMigrationsHistory", "identity")
                    .EnableRetryOnFailure()));

        services.Configure<JwtOptions>(configuration.GetSection(JwtOptions.SectionName));
        services.Configure<PlatformOptions>(configuration.GetSection(PlatformOptions.SectionName));
        services.Configure<EmailOptions>(configuration.GetSection(EmailOptions.SectionName));
        services.Configure<TenantDatabasesOptions>(configuration.GetSection(TenantDatabasesOptions.SectionName));

        services.AddSingleton<ITenantConnectionResolver, TenantConnectionResolver>();
        services.AddSingleton<TenantDataSourcePool>();
        services.AddSingleton<ITenantDbContextFactory, NpgsqlTenantDbContextFactory>();
        services.AddSingleton<ITenantDatabaseMigratorPort, EfTenantDatabaseMigrator>();

        services.AddSingleton<IClockPort, SystemClockAdapter>();
        services.AddSingleton<IPasswordHasherPort, Pbkdf2PasswordHasherAdapter>();
        services.AddSingleton<ITemporaryPasswordGeneratorPort, TemporaryPasswordGeneratorAdapter>();
        services.AddSingleton<ITemporaryPasswordDeliveryPort, SmtpTemporaryPasswordDeliveryAdapter>();
        services.AddSingleton<ITokenIssuerPort, JwtTokenIssuerAdapter>();

        services.AddScoped<IAccountRepository, EfAccountRepository>();
        services.AddScoped<IRefreshTokenRepository, EfRefreshTokenRepository>();
        services.AddScoped<IProvisioningRecordRepository, EfProvisioningRecordRepository>();

        var platformOptions = configuration.GetSection(PlatformOptions.SectionName).Get<PlatformOptions>()
            ?? new PlatformOptions();
        if (string.Equals(platformOptions.Mode, "Grpc", StringComparison.OrdinalIgnoreCase))
        {
            services.AddSingleton(_ =>
            {
                var channel = GrpcChannel.ForAddress(platformOptions.GrpcAddress);
                return new TenantAccessService.TenantAccessServiceClient(channel);
            });
            services.AddScoped<ITenantAccessStatePort, GrpcTenantAccessStateAdapter>();
        }
        else
        {
            services.AddScoped<ITenantAccessStatePort, LocalTenantAccessStateAdapter>();
        }

        services.AddScoped<IdentityDbInitializer>();

        services.AddScoped<LoginClinicUseCase>();
        services.AddScoped<LoginPlatformUseCase>();
        services.AddScoped<RefreshSessionUseCase>();
        services.AddScoped<LogoutUseCase>();
        services.AddScoped<GetCurrentAccountUseCase>();
        services.AddScoped<ChangePasswordUseCase>();
        services.AddScoped<ProvisionInitialClinicAdminUseCase>();

        services.AddScoped<ListTenantStaffUseCase>();
        services.AddScoped<CreateStaffUseCase>();
        services.AddScoped<UpdateStaffRoleUseCase>();
        services.AddScoped<UpdateStaffStatusUseCase>();
        services.AddScoped<UpdateAuxiliaryLinksUseCase>();

        return services;
    }
}
