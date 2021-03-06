﻿using System;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace LabExam.Models.Entities
{
    public class MultipleChoices
    {
        [Key, DatabaseGenerated(DatabaseGeneratedOption.Identity)]
        public int MultipleId { get; set; }

        [ForeignKey("Module")]
        public int ModuleId { get; set; } //编号

        public virtual Module Module { get; set; }

        [Column("Content", TypeName = "ntext")]
        public string Content { get; set; }

        [MaxLength(50)]
        public String Answer { get; set; }

        public float DegreeOfDifficulty { get; set; }

        public DateTime AddTime { get; set; }

        [MaxLength(100)]
        public String PrincipalId { get; set; }

        public int Count { get; set; }

        [MaxLength(200)]
        public String Key { get; set; }

        [MaxLength(2000)]
        public String A { get; set; }

        [MaxLength(2000)]
        public String B { get; set; }

        [MaxLength(2000)]
        public String C { get; set; }

        [MaxLength(2000)]
        public String D { get; set; }

        [MaxLength(2000)]
        public String E { get; set; }

        [MaxLength(2000)]
        public String F { get; set; }

        [MaxLength(2000)]
        public String G { get; set; }

        [MaxLength(2000)]
        public String H { get; set; }
    }
}
