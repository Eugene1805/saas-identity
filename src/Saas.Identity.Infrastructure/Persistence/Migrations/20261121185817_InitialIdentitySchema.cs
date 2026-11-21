using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Saas.Identity.Infrastructure.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class InitialIdentitySchema : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.EnsureSchema(
                name: "identity");

            migrationBuilder.CreateTable(
                name: "accounts",
                schema: "identity",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "uuid", nullable: false),
                    tenant_id = table.Column<Guid>(type: "uuid", nullable: true),
                    full_name = table.Column<string>(type: "character varying(160)", maxLength: 160, nullable: false),
                    email = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: false),
                    normalized_email = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: false),
                    password_hash = table.Column<string>(type: "character varying(300)", maxLength: 300, nullable: false),
                    role = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    active = table.Column<bool>(type: "boolean", nullable: false),
                    must_change_password = table.Column<bool>(type: "boolean", nullable: false, defaultValue: false),
                    failed_login_attempts = table.Column<int>(type: "integer", nullable: false, defaultValue: 0),
                    lockout_until_utc = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    specialty = table.Column<string>(type: "character varying(120)", maxLength: 120, nullable: true),
                    attribution_license_code = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: true),
                    attribution_title = table.Column<string>(type: "character varying(160)", maxLength: 160, nullable: true),
                    attribution_registered_at_gmt6 = table.Column<string>(type: "character varying(40)", maxLength: 40, nullable: true),
                    perm_can_prescribe = table.Column<bool>(type: "boolean", nullable: false),
                    perm_can_register_patients = table.Column<bool>(type: "boolean", nullable: false),
                    perm_can_assign_initial_primary = table.Column<bool>(type: "boolean", nullable: false),
                    perm_can_upload_studies = table.Column<bool>(type: "boolean", nullable: false),
                    created_at_utc = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    linked_specialist_ids = table.Column<string>(type: "jsonb", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_accounts", x => x.id);
                });

            migrationBuilder.CreateTable(
                name: "refresh_tokens",
                schema: "identity",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "uuid", nullable: false),
                    account_id = table.Column<Guid>(type: "uuid", nullable: false),
                    tenant_id = table.Column<Guid>(type: "uuid", nullable: true),
                    token_hash = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: false),
                    expires_at_utc = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    created_at_utc = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    revoked_at_utc = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    revocation_reason = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: true),
                    replaced_by_token_id = table.Column<Guid>(type: "uuid", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_refresh_tokens", x => x.id);
                    table.ForeignKey(
                        name: "FK_refresh_tokens_accounts_account_id",
                        column: x => x.account_id,
                        principalSchema: "identity",
                        principalTable: "accounts",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "role_audit_entries",
                schema: "identity",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "uuid", nullable: false),
                    tenant_id = table.Column<Guid>(type: "uuid", nullable: false),
                    account_id = table.Column<Guid>(type: "uuid", nullable: false),
                    previous_role = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    next_role = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    previous_can_prescribe = table.Column<bool>(type: "boolean", nullable: false),
                    next_can_prescribe = table.Column<bool>(type: "boolean", nullable: false),
                    actor_account_id = table.Column<Guid>(type: "uuid", nullable: false),
                    actor_name = table.Column<string>(type: "character varying(160)", maxLength: 160, nullable: false),
                    occurred_at_utc = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    note = table.Column<string>(type: "character varying(500)", maxLength: 500, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_role_audit_entries", x => x.id);
                    table.ForeignKey(
                        name: "FK_role_audit_entries_accounts_account_id",
                        column: x => x.account_id,
                        principalSchema: "identity",
                        principalTable: "accounts",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "ux_accounts_platform_email",
                schema: "identity",
                table: "accounts",
                column: "normalized_email",
                unique: true,
                filter: "tenant_id IS NULL");

            migrationBuilder.CreateIndex(
                name: "ux_accounts_tenant_email",
                schema: "identity",
                table: "accounts",
                columns: new[] { "tenant_id", "normalized_email" },
                unique: true,
                filter: "tenant_id IS NOT NULL");

            migrationBuilder.CreateIndex(
                name: "ix_refresh_tokens_account_revoked",
                schema: "identity",
                table: "refresh_tokens",
                columns: new[] { "account_id", "revoked_at_utc" });

            migrationBuilder.CreateIndex(
                name: "ux_refresh_tokens_hash",
                schema: "identity",
                table: "refresh_tokens",
                column: "token_hash",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "ix_role_audit_account_occurred",
                schema: "identity",
                table: "role_audit_entries",
                columns: new[] { "account_id", "occurred_at_utc" });

            migrationBuilder.CreateIndex(
                name: "ix_role_audit_tenant",
                schema: "identity",
                table: "role_audit_entries",
                column: "tenant_id");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "refresh_tokens",
                schema: "identity");

            migrationBuilder.DropTable(
                name: "role_audit_entries",
                schema: "identity");

            migrationBuilder.DropTable(
                name: "accounts",
                schema: "identity");
        }
    }
}
