﻿using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Data;
using System.Data.SqlClient;
using System.Linq;
using LabExam.DataSource;
using LabExam.IServices;
using LabExam.Models.Entities;
using LabExam.Models.EntitiyViews;
using LabExam.Models.JsonModel;
using LabExam.Models.Map;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.ValueGeneration.Internal;

namespace LabExam.Controllers
{
    [Authorize(Roles = "Principal")]
    public class ManagerController : Controller
    {

        private readonly IEncryptionDataService _ncryption;
        private readonly LabContext _context;
        private readonly ILoadConfigFileService _config;
        private readonly IHttpContextAnalysisService _analysis;
        private readonly ILoggerService _logger;

        public ManagerController(IEncryptionDataService ncryption, LabContext context, IHttpContextAccessor accessor, ILoadConfigFileService config, IHttpContextAnalysisService analysis, ILoggerService logger)
        {
            _ncryption = ncryption;
            _context = context;
            _config = config;
            _analysis = analysis;
            _logger = logger;
        }

        public IActionResult Page([Required] int index, String sName, String sId,[Required] int iId, [Required] int pid,Boolean isUnder,Boolean isPost,[Required] int grade)
        {
            if (ModelState.IsValid && index > 0)
            {
                String sql = "select * from StudentView where  InstituteId > 0";

                List<SqlParameter> parameters = new List<SqlParameter>();

                if (sName != null && sName.Trim() != "")
                {
                    sql += $" and StudentName like @Name";

                    parameters.Add(new SqlParameter { ParameterName = "@Name", Value = $"%{sName.Trim()}%", SqlDbType = SqlDbType.NVarChar });
                }

                if (sId != null && sId.Trim() != "")
                {
                    sql += $" and StudentId = @StudentId";

                    parameters.Add(new SqlParameter { ParameterName = "@StudentId", Value = sId.Trim(), SqlDbType = SqlDbType.NVarChar });
                }

                if (iId > 0)
                {
                    sql += $" and InstituteId = {iId}";
                }

                if (pid > 0)
                {
                    sql += $" and ProfessionId = {pid}";
                }

                if (isUnder == !isPost)
                {
                    if (isPost)
                    {
                        sql += $" and StudentType = 1";
                    }

                    if (isUnder)
                    {
                        sql += $" and StudentType = 0";
                    }
                }

                if (grade > 2015)
                {
                    sql += $" and Grade = {grade}";
                }

                int pageSize = 10;
                // ReSharper disable once CoVariantArrayConversion
                int dataCount = _context.VStudentMaps.FromSql(sql,parameters.ToArray()).Count();
                int pageCount = dataCount / pageSize;
                int lastCount = dataCount % pageSize;
                if (lastCount > 0)
                {
                    pageCount++;
                }

                if (index > pageCount || index <= 0)
                {
                    return Json(new
                    {
                        isOk = true,
                        lineCount = 0,
                        pageCount = 1, //总共是多少页
                        pageNowIndex = 1, //当前是第几页
                        size = pageSize
                    });
                }
                // ReSharper disable once CoVariantArrayConversion
                var items = _context.VStudentMaps.FromSql(sql, parameters.ToArray()).OrderBy(item => item.InstituteId)
                    .ThenBy(item => item.ProfessionId)
                    .Skip((index - 1) * pageSize).Take(pageSize).Select(val => new
                    {
                        instituteName = val.InstituteName ,
                        professionName = $"{val.ProfessionName}" + (val.ProfessionType == ProfessionType.UnderGraduate ? "[本科生]" : "[研究生]"),
                        professionType = val.ProfessionType,
                        studentId = val.StudentId,
                        studentName =  val.StudentName,
                        grade = val.Grade,
                        phone = val.Phone,
                        birthDate = _logger.FormatDateShortLocal(val.BirthDate),
                        sex = val.Sex == true?"男":"女",
                        studentType =val.StudentType == StudentType.UnderGraduate? "本科生":"研究生",
                        isPassExam = val.IsPassExam? "通过":"未通过",
                        maxExamScore = val.MaxExamScore,
                        maxExamCount = val.MaxExamCount,
                        professionId = val.ProfessionId,
                        email = val.Email,
                        idNumber =val.IDNumber
                    }).ToList();

                return Json(new
                {
                    isOk = true,
                    lineCount = dataCount,
                    PageCount = pageCount, //总共是多少页
                    pageNowIndex = index, //当前是第几页
                    Items = items,
                    size = pageSize
                });

            }
            else
            {
                return Json(new
                {
                    isOk = false,
                    message = $"参数错误,传递了不符合规定的参数"
                });
            }
        }

        public IActionResult EPage([Required] int index, String sName, String sId, [Required] int iId, [Required] int pid, Boolean isUnder, Boolean isPost, [Required] int grade,[Required] int isPass,float leftScore = 0,float rightScore = Int32.MinValue  )
        {
            if (ModelState.IsValid && index > 0)
            {
                String sql = "select * from StudentView where  InstituteId > 0";

                List<SqlParameter> parameters = new List<SqlParameter>();

                if (sName != null && sName.Trim() != "")
                {
                    sql += $" and StudentName like @Name";
                    
                    parameters.Add(new SqlParameter{ ParameterName = "@Name",  Value = $"%{sName.Trim()}%",  SqlDbType = SqlDbType.NVarChar});
                }

                if (sId != null && sId.Trim() != "")
                {
                    sql += $" and StudentId = @StudentId";

                    parameters.Add(new SqlParameter{ ParameterName = "@StudentId", Value = sId.Trim(), SqlDbType = SqlDbType.NVarChar });
                }

                if (iId > 0)
                {
                    sql += $" and InstituteId = @InstituteId";

                    parameters.Add(new SqlParameter { ParameterName = "@InstituteId", Value = iId, SqlDbType = SqlDbType.Int });
                }

                if (pid > 0)
                {
                    sql += $" and ProfessionId = @pid";
                    parameters.Add(new SqlParameter { ParameterName = "@pid", Value = pid, SqlDbType = SqlDbType.Int });
                }

                if (isUnder == !isPost)
                {
                    if (isPost)
                    {
                        sql += $" and StudentType = @sType";
                        parameters.Add(new SqlParameter { ParameterName = "@sType", Value = 1, SqlDbType = SqlDbType.Int });
                    }

                    if (isUnder)
                    {
                        sql += $" and StudentType = @uType";
                        parameters.Add(new SqlParameter { ParameterName = "@uType", Value = 0, SqlDbType = SqlDbType.Int });
                    }
                }

                if (grade > 2015)
                {
                    sql += $" and Grade = @grade";
                    parameters.Add(new SqlParameter { ParameterName = "@grade", Value = grade, SqlDbType = SqlDbType.Int });
                }

                if (isPass >= 0  )
                {
                    sql += $" and IsPassExam = @PassState";
                    Boolean val = (isPass != 0);
                    parameters.Add(new SqlParameter { ParameterName = "@PassState", Value = val, SqlDbType = SqlDbType.Bit });
                }

                sql += $" and MaxExamScore >= @left and  MaxExamScore <= @right";

                parameters.Add(new SqlParameter { ParameterName = "@left", Value = leftScore, SqlDbType = SqlDbType.Real });
                parameters.Add(new SqlParameter { ParameterName = "@right", Value = rightScore, SqlDbType = SqlDbType.Real });

                int pageSize = 12;

                // ReSharper disable once CoVariantArrayConversion
                int dataCount = _context.VStudentMaps.FromSql(sql, parameters.ToArray()).Count();
                int pageCount = dataCount / pageSize;
                int lastCount = dataCount % pageSize;
                if (lastCount > 0)
                {
                    pageCount++;
                }

                if (index > pageCount || index <= 0)
                {
                    return Json(new
                    {
                        isOk = true,
                        lineCount = 0,
                        pageCount = 1, //总共是多少页
                        pageNowIndex = 1, //当前是第几页
                        size = pageSize
                    });
                }

                // ReSharper disable once CoVariantArrayConversion
                var items = _context.VStudentMaps.FromSql(sql, parameters.ToArray())
                    .OrderBy(item => item.InstituteId)
                    .ThenBy(item => item.ProfessionId)
                    .ThenByDescending(item => item.MaxExamScore)
                    .Skip((index - 1) * pageSize).Take(pageSize).Select(val => new
                    {
                        instituteName = val.InstituteName,
                        professionName = $"{val.ProfessionName}" + (val.ProfessionType == ProfessionType.UnderGraduate ? "[本科生]" : "[研究生]"),
                        professionType = val.ProfessionType,
                        studentId = val.StudentId,
                        studentName = val.StudentName,
                        grade = val.Grade,
                        sex = val.Sex == true ? "男" : "女",
                        studentType = val.StudentType == StudentType.UnderGraduate ? "本科生" : "研究生",
                        isPassExam = val.IsPassExam ? "通过" : "未通过",
                        maxExamScore = val.MaxExamScore,
                    }).ToList();

                return Json(new
                {
                    isOk = true,
                    lineCount = dataCount,
                    PageCount = pageCount, //总共是多少页
                    pageNowIndex = index, //当前是第几页
                    Items = items,
                    size = pageSize
                });

            }
            else
            {
                return Json(new
                {
                    isOk = false,
                    error = _analysis.ModelStateDictionaryError(ModelState),
                    message = $"参数错误,传递了不符合规定的参数"
                });
            }
        }

        [HttpGet]
        public IActionResult Create()
        {
            return View();
        }

        /// <summary>
        /// 添加一个学生系统 完成日志记录
        /// </summary>
        /// <param name="student">新的学生信息</param>
        /// <returns></returns>
        [HttpPost]
        public IActionResult Create([Bind(include: "StudentId,IDNumber,InstituteId,Name,ProfessionId,BirthDate,Sex,StudentType,Grade,Email")] Student student)
        {
            if (ModelState.IsValid)
            {
                if (!_analysis.GetLoginUserConfig(HttpContext).Power.StudentManager)
                {
                    return Json(new
                    {
                        isOk = false,
                        title = "错误",
                        message = "你并无学生管理操作权限"
                    });
                }
                Institute ins = _context.Institute.FirstOrDefault(i => i.InstituteId == student.InstituteId);
                Profession pro = _context.Professions.FirstOrDefault(p => p.ProfessionId == student.ProfessionId);
                if (ins == null)
                {
                    return Json(new
                    {
                        isOk = false,
                        title = "错误",
                        message = "参数错误! 学院不存在！ "
                    });
                }
                if (pro == null)
                {
                    return Json(new
                    {
                        isOk = false,
                        title = "错误",
                        message = "参数错误! 专业不存在！ "
                    });
                }
                if (pro.InstituteId != ins.InstituteId)
                {
                    return Json(new
                    {
                        isOk = false,
                        title = "错误",
                        message = "此专业不属于此学院 ！"
                    });
                }
                if (_context.Student.Any(val => val.StudentId == student.StudentId))
                {
                    return Json(new
                    {
                        isOk = false,
                        title = "错误",
                        message = "此学号的学生已经存在！"
                    });
                }
                else
                {
                    var belong =
                        _context.InstituteToModules.FirstOrDefault(im => im.InstituteId == student.InstituteId);

                    if (belong != null)
                    {
                        SystemSetting setting = _config.LoadSystemSetting();
                        Boolean isConfig = setting.ExamModuleSettings.TryGetValue(belong.ModuleId, out var moduleExamSetting);
                        student.MaxExamCount = isConfig ? moduleExamSetting.AllowExamTime : 3;
                    }
                    else
                    {
                        student.MaxExamCount = 3; //系统默认考试次数三次
                    }

                    /* logger start */
                    LogPricipalOperation operation = _logger.GetDefaultLogPricipalOperation(
                        PrincpalOperationCode.AddStudent, $"{student.StudentId}",
                        $"增加学生 学号{student.InstituteId} 名称:{student.Name} ");
                    operation.PrincpalOperationStatus = PrincpalOperationStatus.Success;
                    /* logger end*/

                    student.IsPassExam = false;
                    student.MaxExamScore = 0;
                    student.Password = _ncryption.EncodeByMd5(_ncryption.EncodeByMd5(student.IDNumber.Substring(student.IDNumber.Length - 6,6)));
                    _context.LogPricipalOperations.Add(operation);
                    _context.Student.Add(student);
                    _context.SaveChanges();
                    return Json(new
                    {
                        isOk = true,
                        title = "温馨提示",
                        message = "添加成功！"
                    });
                }
            }
            else
            {
                List<string> errorParamters = new List<string>();
                List<string> Keys = ModelState.Keys.ToList();
                foreach (var key in Keys)
                {
                    var errors = ModelState[key].Errors.ToList();
                    foreach (var error in errors)
                    {
                        errorParamters.Add(error.ErrorMessage);
                    }
                }
                return Json(new
                {
                    error = errorParamters,
                    isOk = false,
                    title = "错误",
                    message = "参数错误!传入了错误的信息！ "
                });
            }
        }

        [HttpGet]
        public IActionResult List()
        {
            return View();
        }

        public IActionResult StuPerson([Required] String sId)
        {
            if (ModelState.IsValid)
            {
                if (!_analysis.GetLoginUserConfig(HttpContext).Power.StudentManager)
                {
                    return Json(new
                    {
                        isOk = false,
                        title = "错误",
                        message = "你并无学生管理操作权限"
                    });
                }
                vStudentMap val = _context.VStudentMaps.FirstOrDefault(stu => stu.StudentId == sId);
                if (val != null)
                {
                    int examCount = _context.ExaminationPapers.Count(p => p.StudentId == sId);
                    int loginCount = _context.LogUserLogin.Count(l => l.ID == sId);
                    int appCount = _context.ApplicationForReExaminations.Count(a=>a.StudentId == sId);
                    float studyTime = _context.Progresses.Where(prg => prg.StudentId == sId).Sum(p => p.StudyTime);
                    return Json(new
                    {
                        isOk = true,
                        instituteName = val.InstituteName,
                        professionName = $"{val.ProfessionName}" + (val.ProfessionType == ProfessionType.UnderGraduate ? "[本科生]" : "[研究生]"),
                        professionType = val.ProfessionType,
                        studentId = val.StudentId,
                        studentName = val.StudentName,
                        grade = val.Grade,
                        phone = val.Phone,
                        birthDate = val.BirthDate,
                        sex = val.Sex == true ? "男" : "女",
                        studentType = val.StudentType == StudentType.UnderGraduate ? "本科生" : "研究生",
                        isPassExam = val.IsPassExam ? "通过" : "未通过",
                        maxExamScore = val.MaxExamScore,
                        maxExamCount = val.MaxExamCount,
                        ExamCount = examCount,
                        LoginCount = loginCount,
                        AppCount = appCount,
                        StudyTime = studyTime,
                        professionId = val.ProfessionId,
                        email = val.Email,
                        idNumber = val.IDNumber
                    });
                }
                else
                {
                    return Json(new
                    {
                        isOk = false,
                        title = "错误信息",
                        message = "学生不存在或者已经被删除了！"
                    });
                }
            }
            else
            {
                return Json(new
                {
                    isOk = false,
                    title = "错误信息",
                    message = "传入的参数错误"
                });
            }
        }

        /// <summary>
        /// 完成日志记录 删除学生
        /// </summary>
        /// <param name="sId"></param>
        /// <returns></returns>
        [HttpPost]
        public IActionResult Delete([Required] String sId)
        {
            if (ModelState.IsValid)
            {
                if (!_analysis.GetLoginUserConfig(HttpContext).Power.StudentManager)
                {
                    return Json(new
                    {
                        isOk = false,
                        title = "错误信息",
                        message = "你并无学生管理操作权限"
                    });
                }
                Student stu = _context.Student.Find(sId);
                if (stu != null)
                {
                    LogPricipalOperation log = _logger.GetDefaultLogPricipalOperation(
                        PrincpalOperationCode.DeleteStudent, $"查询编码:{stu.StudentId}", $"删除学生{stu.Name}");
                    List<ApplicationForReExamination> apps = _context.ApplicationForReExaminations
                        .Where(app => app.StudentId == sId).ToList();
                    if (apps.Count > 0 )
                    {
                        _context.ApplicationForReExaminations.RemoveRange(apps);
                    }

                    log.PrincpalOperationStatus = PrincpalOperationStatus.Success;
                    _context.Add(log);
                    _context.Student.Remove(stu);
                    _context.SaveChanges();
                    return Json(new
                    {
                        isOk = true,
                        title = "提示信息",
                        message = "删除成功！！"
                    });
                }
                else
                {
                    return Json(new
                    {
                        isOk = false,
                        title = "错误信息",
                        message = "学生不存在或者已经被删除了！"
                    });
                }
            }
            else
            {
                return Json(new
                {
                    isOk = false,
                    title = "错误信息",
                    message = "传入的参数错误"
                });
            }
        }

        public IActionResult IsExist([Required] String sId)
        {
            if (ModelState.IsValid)
            {
                if (!_analysis.GetLoginUserConfig(HttpContext).Power.StudentManager)
                {
                    return Json(new
                    {
                        isOk = false,
                        title = "错误信息",
                        message = "你并无学生管理操作权限"
                    });
                }
                var isExisit = _context.Student.Any(val => val.StudentId == sId);
                return Json(new
                {
                    isOk = true,
                    title = "温馨提示",
                    message = $"检查成功,学号为{sId}的学生" + (isExisit?"存在！":"不存在！")
                });
            }
            else
            {
                return Json(new
                {
                    isOk = false,
                    title = "错误提示",
                    message = "传递的参数错误"
                });
            }
        }
        [HttpGet]
        public IActionResult Report()
        {
            return View();
        }

        
        public IActionResult Warning()
        {
            ViewBag.reExam =
                _context.ApplicationForReExaminations.Count(a => a.ApplicationStatus == ApplicationStatus.Submit);
            ViewBag.join =
                _context.ApplicationJoinTheExaminations.Count(a => a.ApplicationStatus == ApplicationStatus.Submit);
            return PartialView();
        }

        [Route("/api/student")]
        [AllowAnonymous]
        public IActionResult Search([Required, MaxLength(20)] String sId)
        {
            if (sId == null)
            {
                return Json(new
                {
                    isOk = false,
                    error = "参数错误！"
                });
            }
            vStudentMap stu = _context.VStudentMaps.FirstOrDefault(v => v.StudentId == sId.Trim());
            if (stu != null)
            {
                float studyTime = _context.Progresses.Where(prg => prg.StudentId == sId).Sum(p => p.StudyTime);
                int examCount = _context.ExaminationPapers.Count(p => p.StudentId == sId);
                return Json(new
                {
                    isOk = true,
                    sId = stu.StudentId,
                    isPassExam = stu.IsPassExam,
                    maxScore = stu.MaxExamScore,
                    institute = stu.InstituteName,
                    type = stu.StudentType,
                    sex = stu.Sex ?"男":"女",
                    grade = stu.Grade,
                    studyTime = studyTime,
                    examCount = examCount
                });
            }
            else
            {
                return Json(new
                {
                    isOk = false,
                    error = "学号在数据库中不存在"
                });
            }
        }

        [AllowAnonymous]
        public IActionResult Keeper()
        {
            Random rand = new Random();
            int index = rand.Next(0, 2);
            ViewBag.StaffName = _config.LoadSystemSetting().Staffs[index].Name;
            ViewBag.StaffPhone = _config.LoadSystemSetting().Staffs[index].Phone;
            ViewBag.StaffQQ = _config.LoadSystemSetting().Staffs[index].QQ;
            ViewBag.index = index;
            return PartialView();
        }

    }
}