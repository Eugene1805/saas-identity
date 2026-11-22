# saas-identity

Microservicio **Identity** de **Vital** (Plataforma SaaS Gestión Hospitalaria), implementado en **.NET 10** con **Arquitectura Hexagonal (Puertos y Adaptadores)**, persistencia en **PostgreSQL**, sesiones con **JWT Bearer + Refresh Tokens rotables**, documentación **OpenAPI / Scalar** y pruebas unitarias (**xUnit**) + integración HTTP (**Postman / Newman**).

## Arquitectura Hexagonal

```text
protos/
  platform_identity/v1/          # Contrato Protobuf congelado compartido con saas-platform
src/
  Saas.Identity.Domain/          # Entidades (incl. ProvisioningRecord), Value Objects, políticas puras (CU-12, CU-13, CU-14, contraseñas, lockout), reloj GMT-6, Result<T>
  Saas.Identity.Application/     # Puertos (incl. ITemporaryPasswordDeliveryPort y IProvisioningRecordRepository) y casos de uso Auth, Personal y Provisioning
  Saas.Identity.Infrastructure/  # Adaptadores salientes: EF Core + Migraciones PostgreSQL, PBKDF2, JWT, Email (LogOnly/SMTP), Cliente gRPC Platform
  Saas.Identity.Api/             # Adaptadores entrantes: Minimal APIs HTTP (:8080), OpenAPI/Scalar y Servidor gRPC HTTP/2 (:8082) + Reflection
tests/
  Saas.Identity.UnitTests/       # Pruebas unitarias xUnit de dominio, casos de uso, lockout, personal, correo y gRPC
  postman/                       # Colección y entorno para Postman / Newman (Incremento 1 + Incremento 2)
```

Regla de dependencias: `Api -> Application -> Domain` y `Infrastructure -> Application -> Domain`. El núcleo (`Domain` + `Application`) no depende de frameworks HTTP, Entity Framework, SMTP ni PostgreSQL.

## Arranque rápido con Docker

```powershell
cd saas-identity
docker compose up -d --build
```

> Nota al actualizar desde Incremento 1: si ya existía el volumen PostgreSQL generado con `EnsureCreated`, ejecuta `docker compose down -v && docker compose up -d --build` para inicializar limpiamente el esquema administrado con migraciones EF Core (`__EFMigrationsHistory`). Las migraciones posteriores (como `AddProvisioningRecords`) se aplican automáticamente con `docker compose up -d --build`.

- API HTTP Identity: `http://127.0.0.1:8081`
- Servidor gRPC (`h2c`): `http://127.0.0.1:5082` (interno contenedor `http://identity-api:8082`)
- Health checks: `http://127.0.0.1:8081/health`, `http://127.0.0.1:8081/health/live` (liveness) y `http://127.0.0.1:8081/health/ready` (readiness con PostgreSQL)
- Documento OpenAPI: `http://127.0.0.1:8081/openapi/v1.json`
- Documentación interactiva Scalar: `http://127.0.0.1:8081/scalar/v1`
- PostgreSQL local (puerto host): `127.0.0.1:5433` (base `vital_identity`)
- Variables clave en Docker:
  - `Email__Mode`: `LogOnly` (desarrollo sin SMTP; no escribe contraseñas en logs) o `Smtp` (`Email__SmtpHost`, `Email__SmtpPort`, `Email__Username`, `Email__Password`).
  - `Platform__Mode`: `Local` (stub local) o `Grpc` (`Platform__GrpcAddress`, por defecto `http://platform-api:8092`).
  - `InternalGrpc__ApiKey` / `Platform__InternalServiceKey`: cabecera `x-internal-service-key` compartida con `saas-platform`.

## Endpoints implementados (Incrementos 1 y 2)

- `GET /health`
- `GET /health/live` (sonda Kubernetes liveness `process-only`)
- `GET /health/ready` (sonda Kubernetes readiness con verificación PostgreSQL)
- `POST /v1/auth/login` (login por `clinicSlug` + bloqueo exponencial ante intentos fallidos)
- `POST /v1/auth/platform/login` (`SUPER_ADMIN` global)
- `POST /v1/auth/refresh` (rotación con detección de reuso)
- `POST /v1/auth/logout`
- `POST /v1/auth/change-password` (política 8-40 chars: letra, número y símbolo)
- `GET /v1/auth/me`
- `GET /v1/staff` (`CU-12`, cuota `maxActiveAccounts`, historial de auditoría)
- `POST /v1/staff` (`CU-12` alta con contraseña temporal autogenerada en Identity y control `CU-17 A2`)
- `PUT /v1/staff/{accountId}/role` (`CU-14` cambio de rol y atribución con auditoría GMT-6)
- `PATCH /v1/staff/{accountId}/status` (baja/reactivación protegiendo al último `ADMIN_CLINICA` y cuota)
- `PUT /v1/staff/{accountId}/links` (`CU-12` vínculo auxiliar con especialistas activos)

## Pruebas automatizadas

### 1. Pruebas unitarias xUnit dentro de contenedor .NET 10

```powershell
docker build --target test -t vital-identity-test .
```

### 2. Pruebas Postman con Newman contra el stack levantado

```powershell
docker run --rm --network saas-identity_default `
  -v "${PWD}/tests/postman:/etc/newman" `
  postman/newman:alpine run /etc/newman/Vital.Identity.postman_collection.json `
  --env-var "baseUrl=http://identity-api:8080"
```

## CI y publicación de imagen en GHCR

El workflow [`.github/workflows/ci.yml`](.github/workflows/ci.yml) replica el estándar de `saas-platform` y `saas-infra`:

- **PR y push a `develop`/`main`:**
  - `build-and-test` (`contents: read`): `dotnet restore`, `build` y `test` en `.NET 10`.
  - `docker-build` (`contents: read`): construye la imagen con etiquetas OCI, ejecuta PostgreSQL 17 + `saas-identity` (`--cap-drop=ALL`, `--security-opt=no-new-privileges:true`, usuario no root `$APP_UID`), valida `/health/live`, `/health/ready`, `/health`, `/openapi/v1.json` y corre la colección Postman/Newman completa.
- **Push a `main` (`publish-ghcr`, `packages: write`):**
  - Publica la misma imagen validada en `ghcr.io/eugene1805/saas-identity:<SHA>` (sin sobrescribir `latest`) registrando su digest inmutable `@sha256:...` en `GITHUB_STEP_SUMMARY` para su posterior promoción en `saas-infra`.

Para ver las decisiones abiertas, alcance por incrementos y pendientes con `saas-platform`, consulta `../SEGUIMIENTO_IDENTITY_BACKEND.md`.
