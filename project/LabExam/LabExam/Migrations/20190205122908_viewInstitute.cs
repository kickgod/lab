﻿using Microsoft.EntityFrameworkCore.Migrations;

namespace LabExam.Migrations
{
    public partial class viewInstitute : Migration
    {
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.EnsureSchema(
                name: "dbo");
        }

        protected override void Down(MigrationBuilder migrationBuilder)
        {

        }
    }
}
