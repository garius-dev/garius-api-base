using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace GariusWeb.Api.Infrastructure.Data.Migrations
{
    /// <inheritdoc />
    public partial class FeedDefaultRoles : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.InsertData(
                table: "AspNetRoles", // Nome da tabela de roles do Identity (geralmente AspNetRoles)
                columns: new[] { "Id", "Name", "NormalizedName", "Description", "Level", "ConcurrencyStamp" }, // Colunas a serem inseridas
                values: new object[,]
                {
                    { "0198801d-f235-7c32-8d1f-1d216b0b7032", "Developer", "DEVELOPER", "Desenvolvedor do sistema", 0, Guid.NewGuid().ToString() },
                    { "01988a9c-2bfc-70d5-a6dc-22f911179bd0", "Owner", "OWNER", "Dono do sistema", 1, Guid.NewGuid().ToString() },
                    { "01988035-d4b4-7896-8222-7e20fd0a7a90", "Admin", "ADMIN", "Administrador do sistema", 2, Guid.NewGuid().ToString() },
                    { "3cd743ab-14be-4606-81ac-1c5d79f6a54a", "User", "USER", "Usuário padrão", 10, Guid.NewGuid().ToString() }
                }
            );
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {

        }
    }
}
