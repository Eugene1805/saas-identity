using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Saas.Identity.Infrastructure.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class AddProvisioningRecords : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "provisioning_records",
                schema: "identity",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "uuid", nullable: false),
                    tenant_id = table.Column<Guid>(type: "uuid", nullable: false),
                    provisioning_request_id = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: false),
                    clinic_slug = table.Column<string>(type: "character varying(120)", maxLength: 120, nullable: false),
                    clinic_name = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: false),
                    admin_full_name = table.Column<string>(type: "character varying(160)", maxLength: 160, nullable: false),
                    admin_email = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: false),
                    normalized_admin_email = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: false),
                    initial_admin_account_id = table.Column<Guid>(type: "uuid", nullable: true),
                    status = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    temporary_password_email_sent = table.Column<bool>(type: "boolean", nullable: false, defaultValue: false),
                    last_error_code = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: true),
                    created_at_utc = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    updated_at_utc = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_provisioning_records", x => x.id);
                    table.ForeignKey(
                        name: "FK_provisioning_records_accounts_initial_admin_account_id",
                        column: x => x.initial_admin_account_id,
                        principalSchema: "identity",
                        principalTable: "accounts",
                        principalColumn: "id",
                        onDelete: ReferentialAction.SetNull);
                });

            migrationBuilder.CreateIndex(
                name: "IX_provisioning_records_initial_admin_account_id",
                schema: "identity",
                table: "provisioning_records",
                column: "initial_admin_account_id");

            migrationBuilder.CreateIndex(
                name: "ix_provisioning_records_tenant_id",
                schema: "identity",
                table: "provisioning_records",
                column: "tenant_id");

            migrationBuilder.CreateIndex(
                name: "ux_provisioning_records_request_id",
                schema: "identity",
                table: "provisioning_records",
                column: "provisioning_request_id",
                unique: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "provisioning_records",
                schema: "identity");
        }
    }
}
