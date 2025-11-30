using Microsoft.EntityFrameworkCore.Migrations;

namespace jVision.Server.Migrations
{
    public partial class DomainAssetSupport : Migration
    {
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "DomainAssets",
                columns: table => new
                {
                    DomainAssetId = table.Column<int>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    BoxId = table.Column<int>(type: "INTEGER", nullable: true),
                    Hostname = table.Column<string>(type: "TEXT", nullable: false),
                    DomainName = table.Column<string>(type: "TEXT", nullable: true),
                    DistinguishedName = table.Column<string>(type: "TEXT", nullable: true),
                    Role = table.Column<string>(type: "TEXT", nullable: true),
                    Ip = table.Column<string>(type: "TEXT", nullable: true),
                    IsDomainController = table.Column<bool>(type: "INTEGER", nullable: false),
                    Notes = table.Column<string>(type: "TEXT", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_DomainAssets", x => x.DomainAssetId);
                    table.ForeignKey(
                        name: "FK_DomainAssets_Boxes_BoxId",
                        column: x => x.BoxId,
                        principalTable: "Boxes",
                        principalColumn: "BoxId",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateIndex(
                name: "IX_DomainAssets_BoxId",
                table: "DomainAssets",
                column: "BoxId");
        }

        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "DomainAssets");
        }
    }
}
