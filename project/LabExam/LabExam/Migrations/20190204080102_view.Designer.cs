﻿// <auto-generated />
using System;
using LabExam.DataSource;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Metadata;
using Microsoft.EntityFrameworkCore.Migrations;
using Microsoft.EntityFrameworkCore.Storage.ValueConversion;

namespace LabExam.Migrations
{
    [DbContext(typeof(LabContext))]
    [Migration("20190204080102_view")]
    partial class view
    {
        protected override void BuildTargetModel(ModelBuilder modelBuilder)
        {
#pragma warning disable 612, 618
            modelBuilder
                .HasAnnotation("ProductVersion", "2.1.4-rtm-31024")
                .HasAnnotation("Relational:MaxIdentifierLength", 128)
                .HasAnnotation("SqlServer:ValueGenerationStrategy", SqlServerValueGenerationStrategy.IdentityColumn);

            modelBuilder.Entity("LabExam.Models.Entities.ApplicationForReExamination", b =>
                {
                    b.Property<int>("ApplicationExamId")
                        .ValueGeneratedOnAdd()
                        .HasAnnotation("SqlServer:ValueGenerationStrategy", SqlServerValueGenerationStrategy.IdentityColumn);

                    b.Property<int>("ApplicationStatus");

                    b.Property<string>("Email")
                        .HasMaxLength(500);

                    b.Property<int>("InstituteId");

                    b.Property<int>("ModuleId");

                    b.Property<string>("Reason")
                        .HasColumnName("Reason")
                        .HasColumnType("ntext");

                    b.Property<string>("StudentId")
                        .HasMaxLength(40);

                    b.HasKey("ApplicationExamId");

                    b.HasIndex("StudentId");

                    b.ToTable("ApplicationForReExaminations");
                });

            modelBuilder.Entity("LabExam.Models.Entities.ApplicationJoinTheExamination", b =>
                {
                    b.Property<int>("ApplicationJoinId")
                        .ValueGeneratedOnAdd()
                        .HasAnnotation("SqlServer:ValueGenerationStrategy", SqlServerValueGenerationStrategy.IdentityColumn);

                    b.Property<int>("ApplicationStatus");

                    b.Property<DateTime>("BirthDate");

                    b.Property<string>("Email")
                        .HasMaxLength(300);

                    b.Property<int>("Grade");

                    b.Property<string>("IDNumber")
                        .HasMaxLength(300);

                    b.Property<int>("InstituteId");

                    b.Property<string>("Name")
                        .HasMaxLength(80);

                    b.Property<string>("Phone")
                        .HasMaxLength(100);

                    b.Property<int>("ProfessionId");

                    b.Property<string>("Reason")
                        .HasColumnName("Reason")
                        .HasColumnType("ntext");

                    b.Property<bool>("Sex");

                    b.Property<string>("StudentId")
                        .HasMaxLength(40);

                    b.Property<int>("StudentType");

                    b.HasKey("ApplicationJoinId");

                    b.ToTable("ApplicationJoinTheExaminations");
                });

            modelBuilder.Entity("LabExam.Models.Entities.Cource", b =>
                {
                    b.Property<int>("CourceId")
                        .ValueGeneratedOnAdd()
                        .HasAnnotation("SqlServer:ValueGenerationStrategy", SqlServerValueGenerationStrategy.IdentityColumn);

                    b.Property<DateTime>("AddTime");

                    b.Property<int>("CourceStatus");

                    b.Property<float>("Credit");

                    b.Property<string>("Introduction");

                    b.Property<int>("ModuleId");

                    b.Property<string>("Name")
                        .HasMaxLength(300);

                    b.Property<string>("PrincipalId")
                        .HasMaxLength(100);

                    b.HasKey("CourceId");

                    b.HasIndex("ModuleId");

                    b.HasIndex("PrincipalId");

                    b.ToTable("Cources");
                });

            modelBuilder.Entity("LabExam.Models.Entities.ExaminationPaper", b =>
                {
                    b.Property<int>("PaperId")
                        .ValueGeneratedOnAdd()
                        .HasAnnotation("SqlServer:ValueGenerationStrategy", SqlServerValueGenerationStrategy.IdentityColumn);

                    b.Property<DateTime>("AddTime");

                    b.Property<float>("ExamTime");

                    b.Property<float>("LeaveExamTime");

                    b.Property<float>("PassScore");

                    b.Property<string>("StudentId")
                        .HasMaxLength(40);

                    b.Property<float>("TotleScore");

                    b.HasKey("PaperId");

                    b.ToTable("ExaminationPapers");
                });

            modelBuilder.Entity("LabExam.Models.Entities.ExamJudgeChoices", b =>
                {
                    b.Property<int>("ExamJudgeChoicesId")
                        .ValueGeneratedOnAdd()
                        .HasAnnotation("SqlServer:ValueGenerationStrategy", SqlServerValueGenerationStrategy.IdentityColumn);

                    b.Property<int>("JudgeId");

                    b.Property<int>("PaperId");

                    b.Property<string>("RealAnswer");

                    b.Property<float>("Score");

                    b.Property<string>("StudentAnswer")
                        .HasMaxLength(10);

                    b.Property<string>("StudentId")
                        .HasMaxLength(40);

                    b.HasKey("ExamJudgeChoicesId");

                    b.HasIndex("JudgeId");

                    b.HasIndex("PaperId");

                    b.ToTable("ExamJudgeChoices");
                });

            modelBuilder.Entity("LabExam.Models.Entities.ExamMultipleChoices", b =>
                {
                    b.Property<int>("ExamMultipleChoicesId")
                        .ValueGeneratedOnAdd()
                        .HasAnnotation("SqlServer:ValueGenerationStrategy", SqlServerValueGenerationStrategy.IdentityColumn);

                    b.Property<int>("MultipleId");

                    b.Property<int>("PaperId");

                    b.Property<string>("RealAnswer");

                    b.Property<float>("Score");

                    b.Property<string>("StudentAnswer")
                        .HasMaxLength(10);

                    b.Property<string>("StudentId")
                        .HasMaxLength(40);

                    b.HasKey("ExamMultipleChoicesId");

                    b.HasIndex("MultipleId");

                    b.HasIndex("PaperId");

                    b.ToTable("ExamMultipleChoices");
                });

            modelBuilder.Entity("LabExam.Models.Entities.ExamSingleChoices", b =>
                {
                    b.Property<int>("ExamSingleChoicesId")
                        .ValueGeneratedOnAdd()
                        .HasAnnotation("SqlServer:ValueGenerationStrategy", SqlServerValueGenerationStrategy.IdentityColumn);

                    b.Property<int>("PaperId");

                    b.Property<string>("RealAnswer");

                    b.Property<float>("Score");

                    b.Property<int>("SingleId");

                    b.Property<string>("StudentAnswer")
                        .HasMaxLength(10);

                    b.Property<string>("StudentId")
                        .HasMaxLength(40);

                    b.HasKey("ExamSingleChoicesId");

                    b.HasIndex("PaperId");

                    b.HasIndex("SingleId");

                    b.ToTable("ExamSingleChoices");
                });

            modelBuilder.Entity("LabExam.Models.Entities.Institute", b =>
                {
                    b.Property<int>("InstituteId")
                        .ValueGeneratedOnAdd()
                        .HasAnnotation("SqlServer:ValueGenerationStrategy", SqlServerValueGenerationStrategy.IdentityColumn);

                    b.Property<string>("Name")
                        .HasMaxLength(80);

                    b.HasKey("InstituteId");

                    b.ToTable("Institute");
                });

            modelBuilder.Entity("LabExam.Models.Entities.InstituteToModule", b =>
                {
                    b.Property<int>("InstituteToModuleId")
                        .ValueGeneratedOnAdd()
                        .HasAnnotation("SqlServer:ValueGenerationStrategy", SqlServerValueGenerationStrategy.IdentityColumn);

                    b.Property<int>("InstituteId");

                    b.Property<int>("ModuleId");

                    b.HasKey("InstituteToModuleId");

                    b.HasIndex("InstituteId");

                    b.HasIndex("ModuleId");

                    b.ToTable("InstituteToModules");
                });

            modelBuilder.Entity("LabExam.Models.Entities.JudgeChoices", b =>
                {
                    b.Property<int>("JudgeId")
                        .ValueGeneratedOnAdd()
                        .HasAnnotation("SqlServer:ValueGenerationStrategy", SqlServerValueGenerationStrategy.IdentityColumn);

                    b.Property<string>("A")
                        .HasMaxLength(1000);

                    b.Property<DateTime>("AddTime");

                    b.Property<string>("Answer")
                        .HasMaxLength(10);

                    b.Property<string>("B")
                        .HasMaxLength(1000);

                    b.Property<string>("Content")
                        .HasColumnName("Content")
                        .HasColumnType("ntext");

                    b.Property<int>("Count");

                    b.Property<float>("DegreeOfDifficulty");

                    b.Property<int>("ModuleId");

                    b.Property<string>("PrincipalId")
                        .HasMaxLength(100);

                    b.HasKey("JudgeId");

                    b.HasIndex("ModuleId");

                    b.ToTable("JudgeChoices");
                });

            modelBuilder.Entity("LabExam.Models.Entities.Learing", b =>
                {
                    b.Property<int>("LearingId")
                        .ValueGeneratedOnAdd()
                        .HasAnnotation("SqlServer:ValueGenerationStrategy", SqlServerValueGenerationStrategy.IdentityColumn);

                    b.Property<DateTime>("AddTime");

                    b.Property<int>("CourceId");

                    b.Property<string>("StudentId")
                        .HasMaxLength(40);

                    b.HasKey("LearingId");

                    b.HasIndex("CourceId");

                    b.HasIndex("StudentId");

                    b.ToTable("Learings");
                });

            modelBuilder.Entity("LabExam.Models.Entities.LogPricipalOperation", b =>
                {
                    b.Property<int>("LogPricipalOperationId")
                        .ValueGeneratedOnAdd()
                        .HasAnnotation("SqlServer:ValueGenerationStrategy", SqlServerValueGenerationStrategy.IdentityColumn);

                    b.Property<DateTime>("AddTime");

                    b.Property<string>("OperationIp")
                        .HasMaxLength(50);

                    b.Property<string>("PrincipalId")
                        .HasMaxLength(100);

                    b.Property<int>("PrincpalOperationCode");

                    b.Property<string>("PrincpalOperationContent")
                        .HasMaxLength(300);

                    b.Property<string>("PrincpalOperationName")
                        .HasMaxLength(40);

                    b.Property<int>("PrincpalOperationStatus");

                    b.HasKey("LogPricipalOperationId");

                    b.ToTable("LogPricipalOperations");
                });

            modelBuilder.Entity("LabExam.Models.Entities.LogStudentOperation", b =>
                {
                    b.Property<int>("LogStudentOperationId")
                        .ValueGeneratedOnAdd()
                        .HasAnnotation("SqlServer:ValueGenerationStrategy", SqlServerValueGenerationStrategy.IdentityColumn);

                    b.Property<DateTime>("AddTime");

                    b.Property<string>("OperationIp")
                        .HasMaxLength(50);

                    b.Property<int>("StuOperationCode");

                    b.Property<string>("StuOperationContent")
                        .HasColumnName("StuOperationContent")
                        .HasColumnType("nvarchar(300)");

                    b.Property<string>("StuOperationName")
                        .HasMaxLength(40);

                    b.Property<int>("StuOperationStatus");

                    b.Property<int>("StuOperationType");

                    b.Property<int>("StudentId")
                        .HasMaxLength(80);

                    b.Property<string>("Title");

                    b.HasKey("LogStudentOperationId");

                    b.ToTable("LogStudentOperations");
                });

            modelBuilder.Entity("LabExam.Models.Entities.LogUserLogin", b =>
                {
                    b.Property<int>("LogUserLoginId")
                        .ValueGeneratedOnAdd()
                        .HasAnnotation("SqlServer:ValueGenerationStrategy", SqlServerValueGenerationStrategy.IdentityColumn);

                    b.Property<string>("ID")
                        .HasMaxLength(60);

                    b.Property<string>("LoginIp")
                        .HasMaxLength(100);

                    b.Property<DateTime>("LoginTime");

                    b.Property<int>("Terminal");

                    b.HasKey("LogUserLoginId");

                    b.ToTable("LogUserLogin");
                });

            modelBuilder.Entity("LabExam.Models.Entities.Module", b =>
                {
                    b.Property<int>("ModuleId")
                        .ValueGeneratedOnAdd()
                        .HasAnnotation("SqlServer:ValueGenerationStrategy", SqlServerValueGenerationStrategy.IdentityColumn);

                    b.Property<DateTime>("AddTime");

                    b.Property<string>("Name")
                        .HasMaxLength(200);

                    b.Property<string>("PrincipalId")
                        .HasMaxLength(100);

                    b.HasKey("ModuleId");

                    b.HasIndex("PrincipalId");

                    b.ToTable("Module");
                });

            modelBuilder.Entity("LabExam.Models.Entities.MultipleChoices", b =>
                {
                    b.Property<int>("MultipleId")
                        .ValueGeneratedOnAdd()
                        .HasAnnotation("SqlServer:ValueGenerationStrategy", SqlServerValueGenerationStrategy.IdentityColumn);

                    b.Property<string>("A")
                        .HasMaxLength(1000);

                    b.Property<DateTime>("AddTime");

                    b.Property<string>("Answer")
                        .HasMaxLength(10);

                    b.Property<string>("B")
                        .HasMaxLength(1000);

                    b.Property<string>("C")
                        .HasMaxLength(1000);

                    b.Property<string>("Content")
                        .HasColumnName("Content")
                        .HasColumnType("ntext");

                    b.Property<int>("Count");

                    b.Property<string>("D")
                        .HasMaxLength(1000);

                    b.Property<float>("DegreeOfDifficulty");

                    b.Property<string>("E")
                        .HasMaxLength(1000);

                    b.Property<string>("F")
                        .HasMaxLength(1000);

                    b.Property<string>("G")
                        .HasMaxLength(1000);

                    b.Property<string>("H")
                        .HasMaxLength(1000);

                    b.Property<int>("ModuleId");

                    b.Property<string>("PrincipalId")
                        .HasMaxLength(100);

                    b.HasKey("MultipleId");

                    b.HasIndex("ModuleId");

                    b.ToTable("MultipleChoices");
                });

            modelBuilder.Entity("LabExam.Models.Entities.Principal", b =>
                {
                    b.Property<string>("PrincipalId")
                        .ValueGeneratedOnAdd()
                        .HasMaxLength(100);

                    b.Property<string>("JobNumber")
                        .HasMaxLength(50);

                    b.Property<string>("Name")
                        .HasMaxLength(100);

                    b.Property<string>("Password")
                        .HasMaxLength(600);

                    b.Property<string>("Phone")
                        .HasMaxLength(100);

                    b.Property<string>("PrincipalConfig")
                        .HasMaxLength(300);

                    b.Property<int>("PrincipalStatus");

                    b.HasKey("PrincipalId");

                    b.ToTable("Principal");
                });

            modelBuilder.Entity("LabExam.Models.Entities.Profession", b =>
                {
                    b.Property<int>("ProfessionId")
                        .ValueGeneratedOnAdd()
                        .HasAnnotation("SqlServer:ValueGenerationStrategy", SqlServerValueGenerationStrategy.IdentityColumn);

                    b.Property<int>("InstituteId");

                    b.Property<string>("Name")
                        .HasMaxLength(80);

                    b.Property<int>("ProfessionType");

                    b.HasKey("ProfessionId");

                    b.HasIndex("InstituteId");

                    b.ToTable("Professions");
                });

            modelBuilder.Entity("LabExam.Models.Entities.Progress", b =>
                {
                    b.Property<int>("ProgressId")
                        .ValueGeneratedOnAdd()
                        .HasAnnotation("SqlServer:ValueGenerationStrategy", SqlServerValueGenerationStrategy.IdentityColumn);

                    b.Property<DateTime>("AddTime");

                    b.Property<float>("NeedTime");

                    b.Property<int>("ResourceId");

                    b.Property<string>("StudentId")
                        .HasMaxLength(40);

                    b.Property<float>("StudyTime");

                    b.HasKey("ProgressId");

                    b.HasIndex("ResourceId");

                    b.HasIndex("StudentId");

                    b.ToTable("Progresses");
                });

            modelBuilder.Entity("LabExam.Models.Entities.Resource", b =>
                {
                    b.Property<int>("ResourceId")
                        .ValueGeneratedOnAdd()
                        .HasAnnotation("SqlServer:ValueGenerationStrategy", SqlServerValueGenerationStrategy.IdentityColumn);

                    b.Property<int>("CourceId");

                    b.Property<string>("Description")
                        .HasColumnName("Description")
                        .HasColumnType("ntext");

                    b.Property<float>("LengthOfStudy");

                    b.Property<string>("Name")
                        .HasMaxLength(200);

                    b.Property<int>("ResourceStatus");

                    b.Property<int>("ResourceType");

                    b.HasKey("ResourceId");

                    b.HasIndex("CourceId");

                    b.ToTable("Resources");
                });

            modelBuilder.Entity("LabExam.Models.Entities.SingleChoices", b =>
                {
                    b.Property<int>("SingleId")
                        .ValueGeneratedOnAdd()
                        .HasAnnotation("SqlServer:ValueGenerationStrategy", SqlServerValueGenerationStrategy.IdentityColumn);

                    b.Property<string>("A")
                        .HasMaxLength(1000);

                    b.Property<DateTime>("AddTime");

                    b.Property<string>("Answer")
                        .HasMaxLength(10);

                    b.Property<string>("B")
                        .HasMaxLength(1000);

                    b.Property<string>("C")
                        .HasMaxLength(1000);

                    b.Property<string>("Content")
                        .HasColumnName("Content")
                        .HasColumnType("ntext");

                    b.Property<int>("Count");

                    b.Property<string>("D")
                        .HasMaxLength(1000);

                    b.Property<float>("DegreeOfDifficulty");

                    b.Property<string>("E")
                        .HasMaxLength(1000);

                    b.Property<string>("F")
                        .HasMaxLength(1000);

                    b.Property<string>("G")
                        .HasMaxLength(1000);

                    b.Property<string>("H")
                        .HasMaxLength(1000);

                    b.Property<int>("ModuleId");

                    b.Property<string>("PrincipalId")
                        .HasMaxLength(100);

                    b.HasKey("SingleId");

                    b.HasIndex("ModuleId");

                    b.ToTable("SingleChoices");
                });

            modelBuilder.Entity("LabExam.Models.Entities.Student", b =>
                {
                    b.Property<string>("StudentId")
                        .ValueGeneratedOnAdd()
                        .HasMaxLength(40);

                    b.Property<DateTime>("BirthDate")
                        .ValueGeneratedOnAdd()
                        .HasDefaultValueSql("getdate()");

                    b.Property<string>("Email")
                        .HasMaxLength(300);

                    b.Property<int>("Grade");

                    b.Property<string>("IDNumber")
                        .HasMaxLength(800);

                    b.Property<int>("InstituteId");

                    b.Property<bool>("IsPassExam");

                    b.Property<float>("MaxExamCount");

                    b.Property<float>("MaxExamScore");

                    b.Property<string>("Name")
                        .HasMaxLength(80);

                    b.Property<string>("Password")
                        .HasMaxLength(440);

                    b.Property<string>("Phone")
                        .HasMaxLength(200);

                    b.Property<int>("ProfessionId");

                    b.Property<bool>("Sex");

                    b.Property<int>("StudentType");

                    b.HasKey("StudentId");

                    b.HasIndex("ProfessionId");

                    b.ToTable("Student");
                });

            modelBuilder.Entity("LabExam.Models.Entities.ApplicationForReExamination", b =>
                {
                    b.HasOne("LabExam.Models.Entities.Student", "Student")
                        .WithMany()
                        .HasForeignKey("StudentId");
                });

            modelBuilder.Entity("LabExam.Models.Entities.Cource", b =>
                {
                    b.HasOne("LabExam.Models.Entities.Module", "Module")
                        .WithMany()
                        .HasForeignKey("ModuleId")
                        .OnDelete(DeleteBehavior.Cascade);

                    b.HasOne("LabExam.Models.Entities.Principal", "Principal")
                        .WithMany()
                        .HasForeignKey("PrincipalId");
                });

            modelBuilder.Entity("LabExam.Models.Entities.ExamJudgeChoices", b =>
                {
                    b.HasOne("LabExam.Models.Entities.JudgeChoices", "JudgeChoices")
                        .WithMany()
                        .HasForeignKey("JudgeId")
                        .OnDelete(DeleteBehavior.Cascade);

                    b.HasOne("LabExam.Models.Entities.ExaminationPaper", "ExaminationPaper")
                        .WithMany()
                        .HasForeignKey("PaperId")
                        .OnDelete(DeleteBehavior.Cascade);
                });

            modelBuilder.Entity("LabExam.Models.Entities.ExamMultipleChoices", b =>
                {
                    b.HasOne("LabExam.Models.Entities.MultipleChoices", "MultipleChoices")
                        .WithMany()
                        .HasForeignKey("MultipleId")
                        .OnDelete(DeleteBehavior.Cascade);

                    b.HasOne("LabExam.Models.Entities.ExaminationPaper", "ExaminationPaper")
                        .WithMany("ExamMultipleChoices")
                        .HasForeignKey("PaperId")
                        .OnDelete(DeleteBehavior.Cascade);
                });

            modelBuilder.Entity("LabExam.Models.Entities.ExamSingleChoices", b =>
                {
                    b.HasOne("LabExam.Models.Entities.ExaminationPaper", "ExaminationPaper")
                        .WithMany("ExamSingleChoices")
                        .HasForeignKey("PaperId")
                        .OnDelete(DeleteBehavior.Cascade);

                    b.HasOne("LabExam.Models.Entities.SingleChoices", "SingleChoices")
                        .WithMany()
                        .HasForeignKey("SingleId")
                        .OnDelete(DeleteBehavior.Cascade);
                });

            modelBuilder.Entity("LabExam.Models.Entities.InstituteToModule", b =>
                {
                    b.HasOne("LabExam.Models.Entities.Institute", "Institute")
                        .WithMany()
                        .HasForeignKey("InstituteId")
                        .OnDelete(DeleteBehavior.Cascade);

                    b.HasOne("LabExam.Models.Entities.Module", "Module")
                        .WithMany()
                        .HasForeignKey("ModuleId")
                        .OnDelete(DeleteBehavior.Cascade);
                });

            modelBuilder.Entity("LabExam.Models.Entities.JudgeChoices", b =>
                {
                    b.HasOne("LabExam.Models.Entities.Module", "Module")
                        .WithMany()
                        .HasForeignKey("ModuleId")
                        .OnDelete(DeleteBehavior.Cascade);
                });

            modelBuilder.Entity("LabExam.Models.Entities.Learing", b =>
                {
                    b.HasOne("LabExam.Models.Entities.Cource", "Cource")
                        .WithMany()
                        .HasForeignKey("CourceId")
                        .OnDelete(DeleteBehavior.Cascade);

                    b.HasOne("LabExam.Models.Entities.Student", "Student")
                        .WithMany()
                        .HasForeignKey("StudentId");
                });

            modelBuilder.Entity("LabExam.Models.Entities.Module", b =>
                {
                    b.HasOne("LabExam.Models.Entities.Principal", "Principal")
                        .WithMany()
                        .HasForeignKey("PrincipalId");
                });

            modelBuilder.Entity("LabExam.Models.Entities.MultipleChoices", b =>
                {
                    b.HasOne("LabExam.Models.Entities.Module", "Module")
                        .WithMany()
                        .HasForeignKey("ModuleId")
                        .OnDelete(DeleteBehavior.Cascade);
                });

            modelBuilder.Entity("LabExam.Models.Entities.Profession", b =>
                {
                    b.HasOne("LabExam.Models.Entities.Institute", "Institute")
                        .WithMany()
                        .HasForeignKey("InstituteId")
                        .OnDelete(DeleteBehavior.Cascade);
                });

            modelBuilder.Entity("LabExam.Models.Entities.Progress", b =>
                {
                    b.HasOne("LabExam.Models.Entities.Resource", "Resource")
                        .WithMany()
                        .HasForeignKey("ResourceId")
                        .OnDelete(DeleteBehavior.Cascade);

                    b.HasOne("LabExam.Models.Entities.Student", "Student")
                        .WithMany()
                        .HasForeignKey("StudentId");
                });

            modelBuilder.Entity("LabExam.Models.Entities.Resource", b =>
                {
                    b.HasOne("LabExam.Models.Entities.Cource", "Cource")
                        .WithMany()
                        .HasForeignKey("CourceId")
                        .OnDelete(DeleteBehavior.Cascade);
                });

            modelBuilder.Entity("LabExam.Models.Entities.SingleChoices", b =>
                {
                    b.HasOne("LabExam.Models.Entities.Module", "Module")
                        .WithMany()
                        .HasForeignKey("ModuleId")
                        .OnDelete(DeleteBehavior.Cascade);
                });

            modelBuilder.Entity("LabExam.Models.Entities.Student", b =>
                {
                    b.HasOne("LabExam.Models.Entities.Profession", "Profession")
                        .WithMany("Students")
                        .HasForeignKey("ProfessionId")
                        .OnDelete(DeleteBehavior.Cascade);
                });
#pragma warning restore 612, 618
        }
    }
}
