FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src

COPY Saas.Identity.slnx ./
COPY src/Saas.Identity.Domain/Saas.Identity.Domain.csproj src/Saas.Identity.Domain/
COPY src/Saas.Identity.Application/Saas.Identity.Application.csproj src/Saas.Identity.Application/
COPY src/Saas.Identity.Infrastructure/Saas.Identity.Infrastructure.csproj src/Saas.Identity.Infrastructure/
COPY src/Saas.Identity.Api/Saas.Identity.Api.csproj src/Saas.Identity.Api/
COPY tests/Saas.Identity.UnitTests/Saas.Identity.UnitTests.csproj tests/Saas.Identity.UnitTests/

RUN dotnet restore Saas.Identity.slnx

COPY src/ src/
COPY protos/ protos/
COPY tests/ tests/

RUN dotnet build Saas.Identity.slnx -c Release --no-restore

FROM build AS test
RUN dotnet test Saas.Identity.slnx -c Release --no-build --verbosity normal

FROM build AS publish
RUN dotnet publish src/Saas.Identity.Api/Saas.Identity.Api.csproj -c Release --no-restore -o /app/publish /p:UseAppHost=false

FROM mcr.microsoft.com/dotnet/aspnet:10.0 AS final
WORKDIR /app

ENV ASPNETCORE_HTTP_PORTS=
EXPOSE 8080 8082

COPY --from=publish /app/publish .
USER $APP_UID

ENTRYPOINT ["dotnet", "Saas.Identity.Api.dll"]
