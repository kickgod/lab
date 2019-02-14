﻿using LabExam.Models.Entities;
using LabExam.Models.EntitiyViews;
using Microsoft.EntityFrameworkCore;

namespace LabExam.DataSource
{
    public class LabContext:DbContext
    {
        public LabContext(DbContextOptions<LabContext> options)
            : base(options)
        {
            
        }
        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            base.OnModelCreating(modelBuilder);

            modelBuilder.Entity<Student>()
                .Property(b => b.BirthDate)
                .HasDefaultValueSql("getdate()");


            modelBuilder.Query<vInstituteToModuleMap>().ToView("InstituteToModuleView", "dbo");

            modelBuilder.Query<vInstituteWithoutModuleMap>().ToView("InstituteWithoutModuleView", "dbo");

            modelBuilder.Query<vInstituteStudentCountMap>().ToView("InstituteStudentCountView", "dbo");

            modelBuilder.Query<vInstituteMap>().ToView("InstituteView", "dbo");

            modelBuilder.Query<vInstituteStudentNotPassCountMap>().ToView("InstituteStudentNotPassCountView", "dbo");

            modelBuilder.Query<vProfessionMap>().ToView("ProfessionView", "dbo");

            modelBuilder.Query<vStudentMap>().ToView("StudentView", "dbo");
            
        }
        /* 视图 View */
        public virtual DbQuery<vInstituteToModuleMap> VInstituteToModuleMaps { get; set; }
        public virtual DbQuery<vInstituteWithoutModuleMap> VInstituteWithoutModuleMaps { get; set; }

        public virtual DbQuery<vInstituteStudentCountMap> VInstituteStudentCountMaps { get; set; }

        public virtual DbQuery<vInstituteMap> VInstituteMaps { get; set; }

        public virtual DbQuery<vInstituteStudentNotPassCountMap> VInstituteStudentNotPassCountMaps { get; set; }

        public virtual DbQuery<vProfessionMap> VProfessionMaps { get; set; }

        public virtual DbQuery<vStudentMap> VStudentMaps { get; set; }



        /* 表 Table */
        public virtual DbSet<Module> Modules { get; set; }

        public virtual DbSet<Principal> Principals { get; set; }

        public virtual DbSet<Institute> Institute { get; set; }

        public virtual DbSet<InstituteToModule> InstituteToModules { get; set; }

        public virtual DbSet<Profession> Professions { get; set; }

        public virtual DbSet<Student> Student { get; set; }

        public virtual DbSet<Cource> Cources { get; set; }

        public virtual DbSet<Resource> Resources { get; set; }

        public virtual DbSet<Learing> Learings { get; set; }

        public virtual DbSet<Progress> Progresses { get; set; }

        public virtual DbSet<SingleChoices> SingleChoices { get; set; }

        public virtual DbSet<MultipleChoices> MultipleChoices { get; set; }

        public virtual DbSet<JudgeChoices> JudgeChoices { get; set; }

        public virtual DbSet<ExaminationPaper> ExaminationPapers { get; set;  }

        public virtual DbSet<ExamSingleChoices> ExamSingleChoices { get; set; }

        public virtual DbSet<ExamJudgeChoices> ExamJudgeChoices { get; set; }

        public virtual DbSet<ApplicationJoinTheExamination> ApplicationJoinTheExaminations { get; set; }

        public virtual DbSet<ApplicationForReExamination> ApplicationForReExaminations { get; set; }

        public virtual DbSet<LogStudentOperation> LogStudentOperations { get; set; }

        public virtual  DbSet<LogPricipalOperation> LogPricipalOperations { get; set; }

        public virtual DbSet<LogUserLogin> LogUserLogin { get; set; }

    }
}
