#pragma checksum "F:\四川师范大学实验室安全考试项目\lab\project\LabExam\LabExam\Views\Statistics\Grade.cshtml" "{ff1816ec-aa5e-4d10-87f7-6f4963833460}" "6744f823bc9f5c04239593f2f0372a38aeaa2a41"
// <auto-generated/>
#pragma warning disable 1591
[assembly: global::Microsoft.AspNetCore.Razor.Hosting.RazorCompiledItemAttribute(typeof(AspNetCore.Views_Statistics_Grade), @"mvc.1.0.view", @"/Views/Statistics/Grade.cshtml")]
[assembly:global::Microsoft.AspNetCore.Mvc.Razor.Compilation.RazorViewAttribute(@"/Views/Statistics/Grade.cshtml", typeof(AspNetCore.Views_Statistics_Grade))]
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
#line 1 "F:\四川师范大学实验室安全考试项目\lab\project\LabExam\LabExam\Views\_ViewImports.cshtml"
using LabExam;

#line default
#line hidden
#line 2 "F:\四川师范大学实验室安全考试项目\lab\project\LabExam\LabExam\Views\_ViewImports.cshtml"
using LabExam.Models;

#line default
#line hidden
    [global::Microsoft.AspNetCore.Razor.Hosting.RazorSourceChecksumAttribute(@"SHA1", @"6744f823bc9f5c04239593f2f0372a38aeaa2a41", @"/Views/Statistics/Grade.cshtml")]
    [global::Microsoft.AspNetCore.Razor.Hosting.RazorSourceChecksumAttribute(@"SHA1", @"25a346eec04c34e7426a0411470cd3c767046258", @"/Views/_ViewImports.cshtml")]
    public class Views_Statistics_Grade : global::Microsoft.AspNetCore.Mvc.Razor.RazorPage<dynamic>
    {
        private static readonly global::Microsoft.AspNetCore.Razor.TagHelpers.TagHelperAttribute __tagHelperAttribute_0 = new global::Microsoft.AspNetCore.Razor.TagHelpers.TagHelperAttribute("value", "0", global::Microsoft.AspNetCore.Razor.TagHelpers.HtmlAttributeValueStyle.DoubleQuotes);
        private static readonly global::Microsoft.AspNetCore.Razor.TagHelpers.TagHelperAttribute __tagHelperAttribute_1 = new global::Microsoft.AspNetCore.Razor.TagHelpers.TagHelperAttribute("value", "1", global::Microsoft.AspNetCore.Razor.TagHelpers.HtmlAttributeValueStyle.DoubleQuotes);
        private static readonly global::Microsoft.AspNetCore.Razor.TagHelpers.TagHelperAttribute __tagHelperAttribute_2 = new global::Microsoft.AspNetCore.Razor.TagHelpers.TagHelperAttribute("value", "-1", global::Microsoft.AspNetCore.Razor.TagHelpers.HtmlAttributeValueStyle.DoubleQuotes);
        #line hidden
        #pragma warning disable 0169
        private string __tagHelperStringValueBuffer;
        #pragma warning restore 0169
        private global::Microsoft.AspNetCore.Razor.Runtime.TagHelpers.TagHelperExecutionContext __tagHelperExecutionContext;
        private global::Microsoft.AspNetCore.Razor.Runtime.TagHelpers.TagHelperRunner __tagHelperRunner = new global::Microsoft.AspNetCore.Razor.Runtime.TagHelpers.TagHelperRunner();
        private global::Microsoft.AspNetCore.Razor.Runtime.TagHelpers.TagHelperScopeManager __backed__tagHelperScopeManager = null;
        private global::Microsoft.AspNetCore.Razor.Runtime.TagHelpers.TagHelperScopeManager __tagHelperScopeManager
        {
            get
            {
                if (__backed__tagHelperScopeManager == null)
                {
                    __backed__tagHelperScopeManager = new global::Microsoft.AspNetCore.Razor.Runtime.TagHelpers.TagHelperScopeManager(StartTagHelperWritingScope, EndTagHelperWritingScope);
                }
                return __backed__tagHelperScopeManager;
            }
        }
        private global::Microsoft.AspNetCore.Mvc.TagHelpers.OptionTagHelper __Microsoft_AspNetCore_Mvc_TagHelpers_OptionTagHelper;
        #pragma warning disable 1998
        public async override global::System.Threading.Tasks.Task ExecuteAsync()
        {
#line 1 "F:\四川师范大学实验室安全考试项目\lab\project\LabExam\LabExam\Views\Statistics\Grade.cshtml"
  
    ViewData["Title"] = "实验室安全教育在线-年度统计";
    Layout = "~/Views/Shared/_BackEnd_Layout.cshtml";

#line default
#line hidden
            BeginContext(105, 697, true);
            WriteLiteral(@"
<div class=""admin-searach"">
    <div id=""Search-condition"" class="" bc-clr-white margin-5px  padding-15px border-little-grey-all""
         data-min-width=""1250"">
        <div class=""float-layout"">
            <span class=""margin-left-20px font-size-14 text-muted"">年级：</span>
            <select name=""studentGrade"" id=""studentGrade"" data-height=""24"" data-width=""100""
                    class=""font-size-14 font-weight-400 padding-left-5px ""></select>
            <span for=""orderOne"" class=""margin-left-20px font-size-14 text-muted"">排序方式：</span>
            <select id=""orderOne"" name=""orderOne"" data-height=""26"" data-width=""150"" class=""font-size-12 padding-left-5px "">
                ");
            EndContext();
            BeginContext(802, 33, false);
            __tagHelperExecutionContext = __tagHelperScopeManager.Begin("option", global::Microsoft.AspNetCore.Razor.TagHelpers.TagMode.StartTagAndEndTag, "614c602e5ad04f25ae8d1dc8ffc612cf", async() => {
                BeginContext(820, 6, true);
                WriteLiteral(" 总通过率 ");
                EndContext();
            }
            );
            __Microsoft_AspNetCore_Mvc_TagHelpers_OptionTagHelper = CreateTagHelper<global::Microsoft.AspNetCore.Mvc.TagHelpers.OptionTagHelper>();
            __tagHelperExecutionContext.Add(__Microsoft_AspNetCore_Mvc_TagHelpers_OptionTagHelper);
            __Microsoft_AspNetCore_Mvc_TagHelpers_OptionTagHelper.Value = (string)__tagHelperAttribute_0.Value;
            __tagHelperExecutionContext.AddTagHelperAttribute(__tagHelperAttribute_0);
            await __tagHelperRunner.RunAsync(__tagHelperExecutionContext);
            if (!__tagHelperExecutionContext.Output.IsContentModified)
            {
                await __tagHelperExecutionContext.SetOutputContentAsync();
            }
            Write(__tagHelperExecutionContext.Output);
            __tagHelperExecutionContext = __tagHelperScopeManager.End();
            EndContext();
            BeginContext(835, 18, true);
            WriteLiteral("\r\n                ");
            EndContext();
            BeginContext(853, 34, false);
            __tagHelperExecutionContext = __tagHelperScopeManager.Begin("option", global::Microsoft.AspNetCore.Razor.TagHelpers.TagMode.StartTagAndEndTag, "94af28b91af64cdd86dd1d2477879f13", async() => {
                BeginContext(871, 7, true);
                WriteLiteral(" 研究生通过率");
                EndContext();
            }
            );
            __Microsoft_AspNetCore_Mvc_TagHelpers_OptionTagHelper = CreateTagHelper<global::Microsoft.AspNetCore.Mvc.TagHelpers.OptionTagHelper>();
            __tagHelperExecutionContext.Add(__Microsoft_AspNetCore_Mvc_TagHelpers_OptionTagHelper);
            __Microsoft_AspNetCore_Mvc_TagHelpers_OptionTagHelper.Value = (string)__tagHelperAttribute_1.Value;
            __tagHelperExecutionContext.AddTagHelperAttribute(__tagHelperAttribute_1);
            await __tagHelperRunner.RunAsync(__tagHelperExecutionContext);
            if (!__tagHelperExecutionContext.Output.IsContentModified)
            {
                await __tagHelperExecutionContext.SetOutputContentAsync();
            }
            Write(__tagHelperExecutionContext.Output);
            __tagHelperExecutionContext = __tagHelperScopeManager.End();
            EndContext();
            BeginContext(887, 18, true);
            WriteLiteral("\r\n                ");
            EndContext();
            BeginContext(905, 35, false);
            __tagHelperExecutionContext = __tagHelperScopeManager.Begin("option", global::Microsoft.AspNetCore.Razor.TagHelpers.TagMode.StartTagAndEndTag, "95c07c783a4a4e90b422acaed81ba48d", async() => {
                BeginContext(924, 7, true);
                WriteLiteral(" 本科生通过率");
                EndContext();
            }
            );
            __Microsoft_AspNetCore_Mvc_TagHelpers_OptionTagHelper = CreateTagHelper<global::Microsoft.AspNetCore.Mvc.TagHelpers.OptionTagHelper>();
            __tagHelperExecutionContext.Add(__Microsoft_AspNetCore_Mvc_TagHelpers_OptionTagHelper);
            __Microsoft_AspNetCore_Mvc_TagHelpers_OptionTagHelper.Value = (string)__tagHelperAttribute_2.Value;
            __tagHelperExecutionContext.AddTagHelperAttribute(__tagHelperAttribute_2);
            await __tagHelperRunner.RunAsync(__tagHelperExecutionContext);
            if (!__tagHelperExecutionContext.Output.IsContentModified)
            {
                await __tagHelperExecutionContext.SetOutputContentAsync();
            }
            Write(__tagHelperExecutionContext.Output);
            __tagHelperExecutionContext = __tagHelperScopeManager.End();
            EndContext();
            BeginContext(940, 3595, true);
            WriteLiteral(@"
            </select>
            <button class=""margin-left-20px btn btn-sm btn-primary"" id=""InsertExcel"">
                <span class=""glyphicon glyphicon-plus-sign""></span>
                导出 Excel
            </button>
            <a href=""#"" class=""sr-only btn btn-sm btn-info"" id=""download-link""> <span class=""glyphicon glyphicon-circle-arrow-down""></span> 点击下载</a>
            <button id=""searchInstitute"" class=""float-right  btn btn-sm btn-primary"">
                <span class=""glyphicon glyphicon-search""></span>
                立即搜索
            </button>
        </div>
    </div>
</div>
<div class="" bc-clr-white margin-5px  padding-15px border-little-grey-all"" data-min-width=""1250"">
    <table class=""table table-hover"" id=""student-list"">
        <thead>
            <tr>
                <th>编号</th>
                <th>年级</th>
                <th>总人数</th>
                <th>总通过人数</th>
                <th>研究生</th>
                <th>本科生</th>
                <th>研究生通过</th>
       ");
            WriteLiteral(@"         <th>本科生通过</th>
                <th>总通过率</th>
                <th>研究生通过率</th>
                <th>本科生通过率</th>
            </tr>
        </thead>
        <tbody class=""section-items"">
            
        </tbody>
    </table>
    <div class="" float-layout "">
        <label class="" float-left"">
            共 <span class=""items-count"">0</span> 个信息
        </label>
        <div class="" float-right"">
            <a href=""#"" class="" btn-default btn btn-sm "">
                <span>第</span>
                <span class=""show-page-Index"">
                    1
                </span>
                <span>
                    /
                </span>
                <span class=""show-page-Count"">
                    12
                </span>
                <span>
                    页
                </span>
            </a>
            <button class=""First btn btn-primary btn-sm"">
                <span class=""glyphicon glyphicon-backward""></span>
                首页
        ");
            WriteLiteral(@"    </button>
            <button class=""Previous btn btn-primary btn-sm"">
                <span class=""glyphicon glyphicon-chevron-left""></span>
                上一页
            </button>
            <button class=""Next btn btn-primary btn-sm"">
                下一页 <span class=""glyphicon glyphicon-chevron-right""></span>
            </button>
            <button class=""Last btn btn-primary btn-sm"" data-lastIndex=""1"">
                尾页 <span class=""glyphicon glyphicon-forward""></span>
            </button>
            <select data-options=""true"" class="" margin-left-10px text-center"" data-height=""27"" data-width=""45""></select>
            <button data-skip=""true"" class=""btn btn-sm btn-primary"">跳转</button>
        </div>
    </div>
</div>
<script id=""item-template"" type=""x-tmpl-mustache"">
    {{#items}}
    <tr>
        <td>
            <label class=""label label-primary"">{{index}}</label>
        </td>
        <td>
            {{grade}}
        </td>
        <td>
            {{total}}
  ");
            WriteLiteral(@"      </td>
        <td>
            {{passTotal}}
        </td>
        <td>
            {{postCount}}
        </td>
        <td>
            {{underCount}}
        </td>
        <td>
            {{postPassCount}}
        </td>
        <td>
            {{underPassCount}}
        </td>
        <td>
            {{passTotleRate}}%
        </td>
        <td>
            {{postPassRate}}%
        </td>
        <td>
            {{underPassRate}}%
        </td>
    </tr>
    {{/items}}
</script>
");
            EndContext();
            DefineSection("Scripts", async() => {
                BeginContext(4558, 6091, true);
                WriteLiteral(@"
    <script>
        (function loadInstitute() {
             $.ajax({
            url: ""/Institute/List"",
            type: ""post"",
            dataType: ""json"",
            success: function(data, textStatus, jqXHR) {
                $(""#InstituteId"")
                    .append('<option value=""-1"">-- 所有学院 --</option>');
                for (var index in data) {
                    $(""#InstituteId"")
                        .append(`<option value=""${data[index].instituteId}"">${data[index].name}</option>`);
                }
                LoadYear();
                loadPageByIndex(1);
            },
            error: function(jqXHR, textStatus, errorThrown) {
                onMask(""错误"", errorThrown);
            }
        });
        })();

        $('#InstituteId').change(function(jqEvent) {
            loadPageByIndex(1);
        });

        function LoadYear() {
            var yearNow = new Date().getFullYear();

            $(""#studentGrade"").append('<option value=""-1");
                WriteLiteral(@""">所有年级</option>');
            for (var index = yearNow; index > 2015; index--) {
                $(""#studentGrade"")
                    .append(`<option value=""${index}"">${index}</option>`);
            }
        }

        function stateManager() {
            var pageIndex = parseInt($('.show-page-Index').text().trim()); //当前页
            var pageCount = parseInt($('.show-page-Count').text().trim()); //总共多少页
            if (pageIndex >= pageCount) {
                $('.Next').prop(""disabled"", true);
            } else {
                $('.Next').prop(""disabled"", false);
            }
            if (pageIndex == 1) {
                $('.Previous').prop(""disabled"", true);
            } else {
                $('.Previous').prop(""disabled"", false);
            }
        }

        function loadPageByIndex(index) {
            $.ajax({
                url: ""/Statistics/GPage"",
                type: ""post"",
                dataType: ""json"",
                data: {
                 ");
                WriteLiteral(@"   index: index,
                    grade: $('#studentGrade').val(),
                    orderOne: $('#orderOne').val()
                },
                success: function (json, textStatus, jqXhr) {
                    console.log(json);
                    if (json.isOk) {
                        if (json.items == null) {
                            $('.section-items').html("""");
                        }
                        else
                        {
                            var inCre = json.size * (index - 1);
                            for (var i = 0; i < json.items.length; i++) {
                                json.items[i].index = (i + 1 + inCre);
                            }

                            var template = $('#item-template').html();
                            Mustache.parse(template);
                            var result = Mustache.render(template, json);
                            $('.section-items').html(result);
                        }

     ");
                WriteLiteral(@"                   $('.items-count').text(json.lineCount); //学院总数
                        $('.show-page-Count').text(`${json.pageCount}`); //分页总数
                        $('.show-page-Index').text(`${json.pageNowIndex}`); //当前页
                        $('button[data-lastIndex]').attr(""data-lastIndex"", json.pageCount); //最后一页 的index


                        $('select[data-options] > option').remove();

                        for (let index_ = 0; index_ < json.pageCount; index_++) {
                            $('select[data-options]').append(`<option value=""${index_ + 1}"">${index_ + 1}</option>`);
                        }

                        $('select[data-options]').val(index);

                        stateManager();
                    } else {
                        onMask(""错误"", json.message);
                    }
                },
                error: function(jqXHR, textStatus, errorThrown) {
                    onMask(""错误"", ""网络接连错误.."");
                }
            })");
                WriteLiteral(@";
        }

        $('.Next').click(function(jqEvent) {
            loadPageByIndex(parseInt($('.show-page-Index').text().trim()) + 1);
        });

        $('.First').click(function(jqEvent) {
            loadPageByIndex(1);
        });

        $('.Previous').click(function(jqEvent) {
            loadPageByIndex(parseInt($('.show-page-Index').text().trim()) - 1);
        });

        $('.Last').click(function(jqEvent) {
            loadPageByIndex($('button[data-lastIndex]').attr(""data-lastIndex"").trim());
        });

        $('button[data-skip]').click(function(jqEvent) {
            var pageIndex = parseInt($('.show-page-Index').text().trim());
            var skip = parseInt($('select[data-options]').val().trim());
            if (skip === pageIndex) {
                onMask(""提示信息"", ""跳转页面为当前页面"");
            } else {
                loadPageByIndex($('select[data-options]').val());
            }
        });

        $('#searchInstitute').click(function(jqEvent) {
      ");
                WriteLiteral(@"      loadPageByIndex(1);
        });

        $('#InsertExcel').click(function(jqEvent) {
            $.ajax({
                url: ""/Excel/Grade"",
                type: ""post"",
                dataType: ""json"",
                data: {
                    grade: $('#studentGrade').val(),
                    orderOne: $('#orderOne').val()
                },
                success: function (json, textStatus, jqXhr) {
                    if (json.isOk) {
                        onMask(""消息提示"", ""加载完成"");
                        $('#download-link').attr(""href"", json.url);
                        $('#download-link').removeClass('sr-only');
                    } else {
                        onMask(json.title, json.message);
                    }
                },
                error: function (jqXHR, textStatus, errorThrown) {
                    onMask(""错误"", ""网络接连错误.."");
                }
            });
        });
    </script>
");
                EndContext();
            }
            );
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
        public global::Microsoft.AspNetCore.Mvc.Rendering.IHtmlHelper<dynamic> Html { get; private set; }
    }
}
#pragma warning restore 1591
