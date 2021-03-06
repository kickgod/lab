#pragma checksum "F:\四川师范大学实验室安全考试项目\yun\lab\project\LabExam\LabExam\Views\Student\Course.cshtml" "{ff1816ec-aa5e-4d10-87f7-6f4963833460}" "53e33724f2aa2f5d18f5bfcfeeafd691fdf84d31"
// <auto-generated/>
#pragma warning disable 1591
[assembly: global::Microsoft.AspNetCore.Razor.Hosting.RazorCompiledItemAttribute(typeof(AspNetCore.Views_Student_Course), @"mvc.1.0.view", @"/Views/Student/Course.cshtml")]
[assembly:global::Microsoft.AspNetCore.Mvc.Razor.Compilation.RazorViewAttribute(@"/Views/Student/Course.cshtml", typeof(AspNetCore.Views_Student_Course))]
namespace AspNetCore
{
    #line hidden
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Threading.Tasks;
    using Microsoft.AspNetCore.Mvc;
    using Microsoft.AspNetCore.Mvc.Rendering;
    using Microsoft.AspNetCore.Mvc.ViewFeatures;
#line 1 "F:\四川师范大学实验室安全考试项目\yun\lab\project\LabExam\LabExam\Views\_ViewImports.cshtml"
using LabExam;

#line default
#line hidden
#line 2 "F:\四川师范大学实验室安全考试项目\yun\lab\project\LabExam\LabExam\Views\_ViewImports.cshtml"
using LabExam.Models;

#line default
#line hidden
    [global::Microsoft.AspNetCore.Razor.Hosting.RazorSourceChecksumAttribute(@"SHA1", @"53e33724f2aa2f5d18f5bfcfeeafd691fdf84d31", @"/Views/Student/Course.cshtml")]
    [global::Microsoft.AspNetCore.Razor.Hosting.RazorSourceChecksumAttribute(@"SHA1", @"25a346eec04c34e7426a0411470cd3c767046258", @"/Views/_ViewImports.cshtml")]
    public class Views_Student_Course : global::Microsoft.AspNetCore.Mvc.Razor.RazorPage<IEnumerable<LabExam.Models.EntitiyViews.vLearningMap>>
    {
        #pragma warning disable 1998
        public async override global::System.Threading.Tasks.Task ExecuteAsync()
        {
            BeginContext(62, 328, true);
            WriteLiteral(@"
<table class=""table table-hover"" id=""student-list"">
    <thead>
        <tr>
            <th>编号</th>
            <th>课程名称</th>
            <th>学习视频数目</th>
            <th>学分</th>
            <th>添加时间</th>
            <th>是否完成</th>
            <th class=""text-right"">操作</th>
        </tr>
    </thead>
    <tbody>
");
            EndContext();
#line 16 "F:\四川师范大学实验室安全考试项目\yun\lab\project\LabExam\LabExam\Views\Student\Course.cshtml"
           int index = 1; 

#line default
#line hidden
            BeginContext(419, 8, true);
            WriteLiteral("        ");
            EndContext();
#line 17 "F:\四川师范大学实验室安全考试项目\yun\lab\project\LabExam\LabExam\Views\Student\Course.cshtml"
         foreach (var item in Model)
        {

#line default
#line hidden
            BeginContext(468, 124, true);
            WriteLiteral("            <tr>\r\n                <td>\r\n                    <label class=\" label label-primary \">\r\n                         ");
            EndContext();
            BeginContext(594, 7, false);
#line 22 "F:\四川师范大学实验室安全考试项目\yun\lab\project\LabExam\LabExam\Views\Student\Course.cshtml"
                     Write(index++);

#line default
#line hidden
            EndContext();
            BeginContext(602, 75, true);
            WriteLiteral("\r\n                    </label>\r\n                </td>\r\n                <td>");
            EndContext();
            BeginContext(678, 9, false);
#line 25 "F:\四川师范大学实验室安全考试项目\yun\lab\project\LabExam\LabExam\Views\Student\Course.cshtml"
               Write(item.Name);

#line default
#line hidden
            EndContext();
            BeginContext(687, 27, true);
            WriteLiteral("</td>\r\n                <td>");
            EndContext();
            BeginContext(715, 11, false);
#line 26 "F:\四川师范大学实验室安全考试项目\yun\lab\project\LabExam\LabExam\Views\Student\Course.cshtml"
               Write(item.RCount);

#line default
#line hidden
            EndContext();
            BeginContext(726, 85, true);
            WriteLiteral("</td>\r\n                <td>\r\n                    <label class=\" label label-primary\">");
            EndContext();
            BeginContext(812, 11, false);
#line 28 "F:\四川师范大学实验室安全考试项目\yun\lab\project\LabExam\LabExam\Views\Student\Course.cshtml"
                                                   Write(item.Credit);

#line default
#line hidden
            EndContext();
            BeginContext(823, 82, true);
            WriteLiteral("</label>\r\n                </td>\r\n                <td>\r\n                    <small>");
            EndContext();
            BeginContext(906, 12, false);
#line 31 "F:\四川师范大学实验室安全考试项目\yun\lab\project\LabExam\LabExam\Views\Student\Course.cshtml"
                      Write(item.AddTime);

#line default
#line hidden
            EndContext();
            BeginContext(918, 112, true);
            WriteLiteral("</small>\r\n                </td>\r\n                <td>\r\n                    <label class=\"label label-warning  \">");
            EndContext();
            BeginContext(1032, 24, false);
#line 34 "F:\四川师范大学实验室安全考试项目\yun\lab\project\LabExam\LabExam\Views\Student\Course.cshtml"
                                                     Write(item.IsFinish?"完成":"未完成");

#line default
#line hidden
            EndContext();
            BeginContext(1057, 97, true);
            WriteLiteral("</label>\r\n                </td>\r\n                <td class=\" text-right\">\r\n                    <a");
            EndContext();
            BeginWriteAttribute("href", " href=\"", 1154, "\"", 1195, 2);
            WriteAttributeValue("", 1161, "/Student/Video?lId=", 1161, 19, true);
#line 37 "F:\四川师范大学实验室安全考试项目\yun\lab\project\LabExam\LabExam\Views\Student\Course.cshtml"
WriteAttributeValue("", 1180, item.LearingId, 1180, 15, false);

#line default
#line hidden
            EndWriteAttribute();
            BeginContext(1196, 196, true);
            WriteLiteral(" target=\"_blank\"  class=\" btn btn-primary btn-sm \">\r\n                        <span class=\"glyphicon glyphicon-ok\"></span> 开始学习\r\n                    </a>\r\n                </td>\r\n            </tr>\r\n");
            EndContext();
#line 42 "F:\四川师范大学实验室安全考试项目\yun\lab\project\LabExam\LabExam\Views\Student\Course.cshtml"
        }

#line default
#line hidden
            BeginContext(1403, 24, true);
            WriteLiteral("    </tbody>\r\n</table>\r\n");
            EndContext();
        }
        #pragma warning restore 1998
        [global::Microsoft.AspNetCore.Mvc.Razor.Internal.RazorInjectAttribute]
        public global::Microsoft.AspNetCore.Mvc.ViewFeatures.IModelExpressionProvider ModelExpressionProvider { get; private set; }
        [global::Microsoft.AspNetCore.Mvc.Razor.Internal.RazorInjectAttribute]
        public global::Microsoft.AspNetCore.Mvc.IUrlHelper Url { get; private set; }
        [global::Microsoft.AspNetCore.Mvc.Razor.Internal.RazorInjectAttribute]
        public global::Microsoft.AspNetCore.Mvc.IViewComponentHelper Component { get; private set; }
        [global::Microsoft.AspNetCore.Mvc.Razor.Internal.RazorInjectAttribute]
        public global::Microsoft.AspNetCore.Mvc.Rendering.IJsonHelper Json { get; private set; }
        [global::Microsoft.AspNetCore.Mvc.Razor.Internal.RazorInjectAttribute]
        public global::Microsoft.AspNetCore.Mvc.Rendering.IHtmlHelper<IEnumerable<LabExam.Models.EntitiyViews.vLearningMap>> Html { get; private set; }
    }
}
#pragma warning restore 1591
