#pragma checksum "F:\四川师范大学实验室安全考试项目\lab\project\LabExam\LabExam\Views\Judge\Index.cshtml" "{ff1816ec-aa5e-4d10-87f7-6f4963833460}" "f66a7d26b54bc6c296935720e77467ae5981c83d"
// <auto-generated/>
#pragma warning disable 1591
[assembly: global::Microsoft.AspNetCore.Razor.Hosting.RazorCompiledItemAttribute(typeof(AspNetCore.Views_Judge_Index), @"mvc.1.0.view", @"/Views/Judge/Index.cshtml")]
[assembly:global::Microsoft.AspNetCore.Mvc.Razor.Compilation.RazorViewAttribute(@"/Views/Judge/Index.cshtml", typeof(AspNetCore.Views_Judge_Index))]
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
    [global::Microsoft.AspNetCore.Razor.Hosting.RazorSourceChecksumAttribute(@"SHA1", @"f66a7d26b54bc6c296935720e77467ae5981c83d", @"/Views/Judge/Index.cshtml")]
    [global::Microsoft.AspNetCore.Razor.Hosting.RazorSourceChecksumAttribute(@"SHA1", @"25a346eec04c34e7426a0411470cd3c767046258", @"/Views/_ViewImports.cshtml")]
    public class Views_Judge_Index : global::Microsoft.AspNetCore.Mvc.Razor.RazorPage<dynamic>
    {
        private static readonly global::Microsoft.AspNetCore.Razor.TagHelpers.TagHelperAttribute __tagHelperAttribute_0 = new global::Microsoft.AspNetCore.Razor.TagHelpers.TagHelperAttribute("src", new global::Microsoft.AspNetCore.Html.HtmlString("~/lib/validation/jquery.validate.min.js"), global::Microsoft.AspNetCore.Razor.TagHelpers.HtmlAttributeValueStyle.DoubleQuotes);
        private static readonly global::Microsoft.AspNetCore.Razor.TagHelpers.TagHelperAttribute __tagHelperAttribute_1 = new global::Microsoft.AspNetCore.Razor.TagHelpers.TagHelperAttribute("src", new global::Microsoft.AspNetCore.Html.HtmlString("~/lib/validation/additional-methods.min.js"), global::Microsoft.AspNetCore.Razor.TagHelpers.HtmlAttributeValueStyle.DoubleQuotes);
        private static readonly global::Microsoft.AspNetCore.Razor.TagHelpers.TagHelperAttribute __tagHelperAttribute_2 = new global::Microsoft.AspNetCore.Razor.TagHelpers.TagHelperAttribute("src", new global::Microsoft.AspNetCore.Html.HtmlString("~/lib/validation/messages_zh.js"), global::Microsoft.AspNetCore.Razor.TagHelpers.HtmlAttributeValueStyle.DoubleQuotes);
        private static readonly global::Microsoft.AspNetCore.Razor.TagHelpers.TagHelperAttribute __tagHelperAttribute_3 = new global::Microsoft.AspNetCore.Razor.TagHelpers.TagHelperAttribute("id", new global::Microsoft.AspNetCore.Html.HtmlString("create-form"), global::Microsoft.AspNetCore.Razor.TagHelpers.HtmlAttributeValueStyle.DoubleQuotes);
        private static readonly global::Microsoft.AspNetCore.Razor.TagHelpers.TagHelperAttribute __tagHelperAttribute_4 = new global::Microsoft.AspNetCore.Razor.TagHelpers.TagHelperAttribute("class", new global::Microsoft.AspNetCore.Html.HtmlString(" form-horizontal layout-center margin-top-20px "), global::Microsoft.AspNetCore.Razor.TagHelpers.HtmlAttributeValueStyle.DoubleQuotes);
        private static readonly global::Microsoft.AspNetCore.Razor.TagHelpers.TagHelperAttribute __tagHelperAttribute_5 = new global::Microsoft.AspNetCore.Razor.TagHelpers.TagHelperAttribute("data-width", new global::Microsoft.AspNetCore.Html.HtmlString("800"), global::Microsoft.AspNetCore.Razor.TagHelpers.HtmlAttributeValueStyle.DoubleQuotes);
        private static readonly global::Microsoft.AspNetCore.Razor.TagHelpers.TagHelperAttribute __tagHelperAttribute_6 = new global::Microsoft.AspNetCore.Razor.TagHelpers.TagHelperAttribute("class", new global::Microsoft.AspNetCore.Html.HtmlString("update-form"), global::Microsoft.AspNetCore.Razor.TagHelpers.HtmlAttributeValueStyle.DoubleQuotes);
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
        private global::Microsoft.AspNetCore.Mvc.Razor.TagHelpers.UrlResolutionTagHelper __Microsoft_AspNetCore_Mvc_Razor_TagHelpers_UrlResolutionTagHelper;
        private global::Microsoft.AspNetCore.Mvc.TagHelpers.FormTagHelper __Microsoft_AspNetCore_Mvc_TagHelpers_FormTagHelper;
        private global::Microsoft.AspNetCore.Mvc.TagHelpers.RenderAtEndOfFormTagHelper __Microsoft_AspNetCore_Mvc_TagHelpers_RenderAtEndOfFormTagHelper;
        #pragma warning disable 1998
        public async override global::System.Threading.Tasks.Task ExecuteAsync()
        {
            BeginContext(0, 2, true);
            WriteLiteral("\r\n");
            EndContext();
#line 2 "F:\四川师范大学实验室安全考试项目\lab\project\LabExam\LabExam\Views\Judge\Index.cshtml"
  
    ViewData["Title"] = "实验室安全教育在线-判断题题库";
    Layout = "~/Views/Shared/_BackEnd_Layout.cshtml";

#line default
#line hidden
            BeginContext(108, 63, false);
            __tagHelperExecutionContext = __tagHelperScopeManager.Begin("script", global::Microsoft.AspNetCore.Razor.TagHelpers.TagMode.StartTagAndEndTag, "de0453babea546ac9cb9b5b6446d64b5", async() => {
            }
            );
            __Microsoft_AspNetCore_Mvc_Razor_TagHelpers_UrlResolutionTagHelper = CreateTagHelper<global::Microsoft.AspNetCore.Mvc.Razor.TagHelpers.UrlResolutionTagHelper>();
            __tagHelperExecutionContext.Add(__Microsoft_AspNetCore_Mvc_Razor_TagHelpers_UrlResolutionTagHelper);
            __tagHelperExecutionContext.AddHtmlAttribute(__tagHelperAttribute_0);
            await __tagHelperRunner.RunAsync(__tagHelperExecutionContext);
            if (!__tagHelperExecutionContext.Output.IsContentModified)
            {
                await __tagHelperExecutionContext.SetOutputContentAsync();
            }
            Write(__tagHelperExecutionContext.Output);
            __tagHelperExecutionContext = __tagHelperScopeManager.End();
            EndContext();
            BeginContext(171, 2, true);
            WriteLiteral("\r\n");
            EndContext();
            BeginContext(173, 66, false);
            __tagHelperExecutionContext = __tagHelperScopeManager.Begin("script", global::Microsoft.AspNetCore.Razor.TagHelpers.TagMode.StartTagAndEndTag, "8604b55861234fb8858303857d2f9b92", async() => {
            }
            );
            __Microsoft_AspNetCore_Mvc_Razor_TagHelpers_UrlResolutionTagHelper = CreateTagHelper<global::Microsoft.AspNetCore.Mvc.Razor.TagHelpers.UrlResolutionTagHelper>();
            __tagHelperExecutionContext.Add(__Microsoft_AspNetCore_Mvc_Razor_TagHelpers_UrlResolutionTagHelper);
            __tagHelperExecutionContext.AddHtmlAttribute(__tagHelperAttribute_1);
            await __tagHelperRunner.RunAsync(__tagHelperExecutionContext);
            if (!__tagHelperExecutionContext.Output.IsContentModified)
            {
                await __tagHelperExecutionContext.SetOutputContentAsync();
            }
            Write(__tagHelperExecutionContext.Output);
            __tagHelperExecutionContext = __tagHelperScopeManager.End();
            EndContext();
            BeginContext(239, 2, true);
            WriteLiteral("\r\n");
            EndContext();
            BeginContext(241, 55, false);
            __tagHelperExecutionContext = __tagHelperScopeManager.Begin("script", global::Microsoft.AspNetCore.Razor.TagHelpers.TagMode.StartTagAndEndTag, "a6e152a3ad82451984138ec7866ca0fc", async() => {
            }
            );
            __Microsoft_AspNetCore_Mvc_Razor_TagHelpers_UrlResolutionTagHelper = CreateTagHelper<global::Microsoft.AspNetCore.Mvc.Razor.TagHelpers.UrlResolutionTagHelper>();
            __tagHelperExecutionContext.Add(__Microsoft_AspNetCore_Mvc_Razor_TagHelpers_UrlResolutionTagHelper);
            __tagHelperExecutionContext.AddHtmlAttribute(__tagHelperAttribute_2);
            await __tagHelperRunner.RunAsync(__tagHelperExecutionContext);
            if (!__tagHelperExecutionContext.Output.IsContentModified)
            {
                await __tagHelperExecutionContext.SetOutputContentAsync();
            }
            Write(__tagHelperExecutionContext.Output);
            __tagHelperExecutionContext = __tagHelperScopeManager.End();
            EndContext();
            BeginContext(296, 4828, true);
            WriteLiteral(@"
<div class="" margin-5px bc-clr-white  padding-10px border-little-grey-all "" data-height-all>
    <div id=""tablist-hover"">
        <ul class=""nav nav-tabs"" role=""tablist"">
            <li role=""presentation"" class=""active"">
                <a href=""#InstituteList"" aria-controls=""home"" role=""tab"" data-toggle=""tab"">
                    判断题列表
                </a>
            </li>
            <li role=""presentation"">
                <a href=""#addInstitute"" aria-controls=""profile"" role=""tab""
                   data-toggle=""tab"">添加判断题</a>
            </li>
            <li role=""presentation"">
                <a href=""#messages"" aria-controls=""messages"" role=""tab"" data-toggle=""tab"">
                    判断题题库统计
                </a>
            </li>
        </ul>
        <div class=""tab-content"">
            <div role=""tabpanel"" class=""tab-pane active"" id=""InstituteList"">
                <div id=""corporation"" class=""bc-clr-white margin-bottom-10px margin-top-10px padding-10px float-layout"">
   ");
            WriteLiteral(@"                 <label class="" font-size-13 font-weight-500 "">所属模块:</label>
                    <select name=""SerModuleId"" id=""SerModuleId"" class="" padding-left-10px select-layout""
                            data-width=""200"" data-height=""27"">

                    </select>
                    <label class="" font-size-13 font-weight-500 "">上传管理员编号:</label>
                    <input id=""SerPrincipalId"" name=""SerPrincipalId"" value="""" class="" padding-left-10px"" data-width=""180"" data-height=""25"" />
                    <label class="" font-size-13 font-weight-500 "">题干:</label>
                    <input id=""SerContent"" name=""SerContent"" value="""" class="" padding-left-10px"" data-width=""180"" data-height=""25"" />
                    <button   id=""search-items"" class=""float-right btn btn-primary btn-sm margin-left-10px"">
                        <span class=""glyphicon glyphicon-search""></span>
                        立即查询
                    </button>
                </div>
                <div class=""table");
            WriteLiteral(@"-responsive bc-clr-white"">
                    <table class=""table table-hover"" data-min-width=""700"">
                        <thead>
                            <tr>
                                <th>编号</th>
                                <th>所属模块</th>
                                <th>题目内容</th>
                                <th>添加人员编码</th>
                                <th>选项数量</th>
                                <th>添加时间</th>
                                <th>题目类型</th>
                                <th>难度</th>
                                <th class="" text-right"">
                                    题目操作
                                </th>
                            </tr>
                        </thead>
                        <tbody class=""section-items"">

                        </tbody>
                    </table>
                </div>
                <div class="" float-layout bc-clr-white padding-10px "">
                    <label class="" InspageCount float-");
            WriteLiteral(@"left"">
                        共 <span class=""items-count"">0</span> 个题目
                    </label>
                    <div class="" float-right"">
                        <button class="" btn-default btn btn-sm "">
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
                        </button>
                        <button class=""First btn btn-primary btn-sm""> <span class=""glyphicon glyphicon-backward""></span>  首页</button>
                        <button class=""Previous btn btn-primary btn-sm""> <span class=""glyphicon glyphicon-chev");
            WriteLiteral(@"ron-left""></span> 上一页</button>
                        <button class=""Next btn btn-primary btn-sm"">下一页 <span class=""glyphicon glyphicon-chevron-right""></span> </button>
                        <button data-lastIndex="""" class=""Last btn btn-primary btn-sm"">尾页 <span class=""glyphicon glyphicon-forward""></span> </button>
                        <select id=""pageSkipNext"" data-options=""true"" class="" margin-left-10px"" data-height=""27"" data-width=""45"">

                        </select>
                        <button class=""pageSkip btn btn-sm btn-primary"">跳转</button>
                    </div>
                </div>
            </div>
            <div role=""tabpanel"" class=""tab-pane"" id=""addInstitute"">
                ");
            EndContext();
            BeginContext(5124, 2383, false);
            __tagHelperExecutionContext = __tagHelperScopeManager.Begin("form", global::Microsoft.AspNetCore.Razor.TagHelpers.TagMode.StartTagAndEndTag, "5abb92321b0d472baf5b8009d9c4827f", async() => {
                BeginContext(5220, 2280, true);
                WriteLiteral(@"
                    <div class=""form-group"">
                        <label for=""Content"" class=""control-label"">题目题干:</label>
                        <textarea class=""form-control"" name=""Content"" id=""Content""></textarea>
                    </div>
                    <div class=""form-group"">
                        <label for=""Answer"" class=""control-label"">题目答案:</label>
                        <input type=""text"" class="" border-radius-4 margin-left-10px padding-left-10px""
                               value=""""
                               id=""Answer"" name=""Answer"" data-max-width=""120"">
                    </div>
                    <div class=""form-group"">
                        <label for=""name"">所属模块:</label>
                        <select name=""ModuleId"" id=""ModuleId"" class=""form-control border-radius-4 padding-left-10px select-layout"">

                        </select>
                    </div>
                    <div class=""form-group"">
                        <label class=""contr");
                WriteLiteral(@"ol-label"">
                            <span class="" glyphicon glyphicon-ok-sign ""></span>
                            选项数量: 2 
                        </label>
                    </div>
                    <div class=""form-group border-light-down font-weight-600"">
                        <span class=""glyphicon glyphicon-signal text-primary""></span> 选项列表:
                    </div>
                    <div class=""form-group"">
                        <label class=""col-sm-1 control-label"">
                            A：
                        </label>
                        <div class=""col-sm-11"">
                            <p class=""form-control-static border-down-only"">是</p>
                        </div>
                    </div>
                    <div class=""form-group"">
                        <label class=""col-sm-1 control-label"">
                            B：
                        </label>
                        <div class=""col-sm-11"">
                            <p class=");
                WriteLiteral("\"form-control-static border-down-only\">否</p>\r\n                        </div>\r\n                    </div>\r\n                    <button type=\"submit\" class=\"btn btn-primary margin-top-20px form-control\">立即提交</button>\r\n                ");
                EndContext();
            }
            );
            __Microsoft_AspNetCore_Mvc_TagHelpers_FormTagHelper = CreateTagHelper<global::Microsoft.AspNetCore.Mvc.TagHelpers.FormTagHelper>();
            __tagHelperExecutionContext.Add(__Microsoft_AspNetCore_Mvc_TagHelpers_FormTagHelper);
            __Microsoft_AspNetCore_Mvc_TagHelpers_RenderAtEndOfFormTagHelper = CreateTagHelper<global::Microsoft.AspNetCore.Mvc.TagHelpers.RenderAtEndOfFormTagHelper>();
            __tagHelperExecutionContext.Add(__Microsoft_AspNetCore_Mvc_TagHelpers_RenderAtEndOfFormTagHelper);
            __tagHelperExecutionContext.AddHtmlAttribute(__tagHelperAttribute_3);
            __tagHelperExecutionContext.AddHtmlAttribute(__tagHelperAttribute_4);
            __tagHelperExecutionContext.AddHtmlAttribute(__tagHelperAttribute_5);
            await __tagHelperRunner.RunAsync(__tagHelperExecutionContext);
            if (!__tagHelperExecutionContext.Output.IsContentModified)
            {
                await __tagHelperExecutionContext.SetOutputContentAsync();
            }
            Write(__tagHelperExecutionContext.Output);
            __tagHelperExecutionContext = __tagHelperScopeManager.End();
            EndContext();
            BeginContext(7507, 846, true);
            WriteLiteral(@"
            </div>
            <div role=""tabpanel"" class=""tab-pane"" id=""messages"">

            </div>
        </div>
    </div>
</div>
<div class=""modal fade"" id=""detail-dialog"" tabindex=""-1"" role=""dialog"" aria-labelledby=""myModalLabel"" data-backdrop=""static"">
    <div class=""modal-dialog modal-lg"" role=""document"">
        <div class=""modal-content"">
            <div class=""modal-header"">
                <button type=""button"" class=""close"" data-dismiss=""modal"" aria-label=""Close""><span aria-hidden=""true"">&times;</span></button>
                <h4 class=""modal-title font-size-14 font-weight-600 padding-top-10px text-primary"">
                    <span class="" glyphicon glyphicon-comment ""></span>
                    题目信息
                </h4>
            </div>
            <div class=""modal-body"">
                ");
            EndContext();
            BeginContext(8353, 1423, false);
            __tagHelperExecutionContext = __tagHelperScopeManager.Begin("form", global::Microsoft.AspNetCore.Razor.TagHelpers.TagMode.StartTagAndEndTag, "33eed7acf2704adfb1fc68657ef4b604", async() => {
                BeginContext(8380, 1389, true);
                WriteLiteral(@"
                    <div class=""form-group"">
                        <label for=""contextText"" class=""control-label"">题目题干:</label>
                        <textarea class=""form-control"" id=""contextText"" name=""contextText"" ></textarea>
                    </div>
                    <div class=""form-group"">
                        <label for=""recipient-name"" class=""control-label"">题目答案:</label>
                        <input type=""text"" class="" border-radius-4 margin-left-10px padding-left-10px""
                               value=""""
                               id=""answerRe"" name=""answerRe"" data-max-width=""120"">
                    </div>
                    <div class=""form-group"">
                        <label  class=""control-label"">题目选项:A</label>
                        <p class=""form-control-static"">是</p>
                    </div>
                    <div class=""form-group"">
                        <label  class=""control-label"">题目选项:B</label>
                        <p class=""form-cont");
                WriteLiteral(@"rol-static"">否</p>
                    </div>
                    <div class=""form-group"">
                        <button type=""submit"" class="" btn btn-sm btn-primary"">
                            <span class="" glyphicon glyphicon-save""></span>
                            立即保存修改
                        </button>
                    </div>
                ");
                EndContext();
            }
            );
            __Microsoft_AspNetCore_Mvc_TagHelpers_FormTagHelper = CreateTagHelper<global::Microsoft.AspNetCore.Mvc.TagHelpers.FormTagHelper>();
            __tagHelperExecutionContext.Add(__Microsoft_AspNetCore_Mvc_TagHelpers_FormTagHelper);
            __Microsoft_AspNetCore_Mvc_TagHelpers_RenderAtEndOfFormTagHelper = CreateTagHelper<global::Microsoft.AspNetCore.Mvc.TagHelpers.RenderAtEndOfFormTagHelper>();
            __tagHelperExecutionContext.Add(__Microsoft_AspNetCore_Mvc_TagHelpers_RenderAtEndOfFormTagHelper);
            __tagHelperExecutionContext.AddHtmlAttribute(__tagHelperAttribute_6);
            await __tagHelperRunner.RunAsync(__tagHelperExecutionContext);
            if (!__tagHelperExecutionContext.Output.IsContentModified)
            {
                await __tagHelperExecutionContext.SetOutputContentAsync();
            }
            Write(__tagHelperExecutionContext.Output);
            __tagHelperExecutionContext = __tagHelperScopeManager.End();
            EndContext();
            BeginContext(9776, 2549, true);
            WriteLiteral(@"
            </div>
            <div class=""modal-footer"">
                <button type=""button"" class=""btn btn-default btn-sm"" data-dismiss=""modal"">
                    <span class="" glyphicon glyphicon-trash ""></span>
                    立即关闭
                </button>
            </div>
        </div>
    </div>
</div>
<script id=""item-template"" type=""x-tmpl-mustache"">
    {{#items}}
    <tr>
        <td><label class=""label label-primary"">{{index}}</label></td>
        <td><label class=""label label-primary"">{{module.name}}</label></td>
        <td class=""item-content""  width=""250""><small>{{content}}</small></td>
        <td>{{principalId}}</td>
        <td>{{count}}</td>
        <td><small>{{addTime}}</small></td>
        <td>判断题</td>
        <th>{{degreeOfDifficulty}}</th>
        <td class="" text-right "">
            <button class=""delete-dialog btn btn-primary btn-sm"" data-item-id=""{{judgeId}}"">
                <span class=""glyphicon glyphicon-remove""></span>
                删除
");
            WriteLiteral(@"            </button>
            <button class="" detail-dialog btn btn-default btn-sm"" data-item-id=""{{judgeId}}"" data-answer=""{{answer}}"">
                <span class=""glyphicon glyphicon-search""></span>
                详情/修改
            </button>
        </td>
    </tr>
    {{/items}}
</script>
<div class=""modal fade"" id=""delete-dialog"" tabindex=""-1"" role=""dialog"" aria-labelledby=""myModalLabel"">
    <div class=""modal-dialog"" role=""document"">
        <div class=""modal-content"">
            <div class=""modal-header"">
                <button type=""button"" class=""close"" data-dismiss=""modal"" aria-label=""Close""><span aria-hidden=""true"">&times;</span></button>
                <h4 class=""modal-title font-weight-600 font-size-15 padding-top-10px text-primary"" id=""myModalLabel"">删除提示</h4>
            </div>
            <div class=""modal-body"">
                <p class="" text-primary font-size-14"">
                    你确定要删除此题目吗
                </p>
            </div>
            <div class=""modal");
            WriteLiteral(@"-footer"">
                <button type=""button"" class=""btn btn-primary btn-sm"" id=""deleteButton"">
                    <span class="" glyphicon glyphicon-trash ""></span>
                    立即删除
                </button>
                <button type=""button"" class=""btn btn-default btn-sm"" data-dismiss=""modal"">
                    <span class="" glyphicon glyphicon-folder-close ""></span>
                    关闭
                </button>
            </div>
        </div>
    </div>
</div>
");
            EndContext();
            DefineSection("Scripts", async() => {
                BeginContext(12344, 10232, true);
                WriteLiteral(@"
    <script>
        (function loadModuleSelect() {
            $.ajax({
                url: ""/Module/List"",
                type: ""post"",
                dataType: ""json"",
                success: function(data, textStatus, jqXHR) {
                    $(""#SerModuleId"")
                        .append('<option value=""-1"">所有模块</option>');
                    for(var index in data) {
                        $(""#ModuleId"")
                            .append(`<option value=""${data[index].moduleId}"">${data[index].name}</option>`);
                        $(""#SerModuleId"")
                            .append(`<option value=""${data[index].moduleId}"">${data[index].name}</option>`);
                    }
                    loadPageByIndex(1);
                },
                error: function(jqXHR, textStatus, errorThrown) {
                    onMask(""错误"", errorThrown);
                }
            });
        })();

        $(""#create-form"").validate({
            //错误提示信息
          ");
                WriteLiteral(@"  messages: {
                Content: {
                    required: ""请填写题干"",
                    minlength: ""题目允许的最小长度为{0}""
                },
                Answer: {
                    required: ""请填写你的答案""
                }
            },
            //验证规则
            rules: {
                //使用空间 name 名称
                Content: {
                    required: true,
                    minlength: 5
                },
                Answer: {
                    required: true,
                }
            },
            errorClass: ""text-primary"",
            submitHandler: function (form) {
                $.ajax({
                    url: ""/Judge/Create"",
                    type: ""post"",
                    dataType: ""json"",
                    data: {
                        ModuleId: $('#ModuleId').val(),
                        Content: $('#Content').val(),
                        Answer: $(""#Answer"").val()
                    },
                    success: fu");
                WriteLiteral(@"nction (json, textStatus, jqXhr) {
                        //debug
                          console.log(json);

                        //end debug
                        if (json.isOk) {
                            form.reset();
                            loadPageByIndex(1);
                            onMask(json.title, json.message);
                        } else {
                            onMask(json.title, json.message);
                        }
                    },
                    error: function (jqXHR, textStatus, errorThrown) {
                        onMask(""错误"", ""网络连接失败..."");
                    }
                });
            }
        });

        function stateManager() {
            var pageIndex = parseInt($('.show-page-Index').text().trim()); //当前页
            var pageCount = parseInt($('.show-page-Count').text().trim()); //总共多少页
            if (pageIndex >= pageCount) {
                $('.Next').prop(""disabled"", true);
            } else {
         ");
                WriteLiteral(@"       $('.Next').prop(""disabled"", false);
            }
            if (pageIndex == 1) {
                $('.Previous').prop(""disabled"", true);
            } else {
                $('.Previous').prop(""disabled"", false);
            }
        }

        function loadPageByIndex(index) {
            $.ajax({
                url: ""/Judge/Page"",
                type: ""post"",
                dataType: ""json"",
                data: {
                    index: index,
                    mId: $('#corporation select[name=""SerModuleId""]').val(),
                    pId: $('#corporation input[name=""SerPrincipalId""]').val(),
                    content: $('#corporation input[name=""SerContent""]').val()
                },
                success: function (json, textStatus, jqXhr) {
                    //debug
                    console.log(json);
                    // end debug

                    if (json.isOk) {
                        if (json.items == null) {
                         ");
                WriteLiteral(@"   $('.section-items').html("""");
                        } else {
                            for (var i = 0; i < json.items.length; i++) {
                                json.items[i].index = (i + 1);
                            }

                            var template = $('#item-template').html();
                            Mustache.parse(template);
                            var result = Mustache.render(template, json);
                            $('.section-items').html(result);
                        }

                        $('.items-count').text(json.lineCount); //总数
                        $('.show-page-Count').text(`${json.pageCount}`); //分页总数
                        $('.show-page-Index').text(`${json.pageNowIndex}`); //当前页
                        $('button[data-lastIndex]').attr(""data-lastIndex"", json.pageCount); //最后一页 的index

                        $('select[data-options] > option').remove();
                        for (let index_ = 0; index_ < json.pageCount; index_+");
                WriteLiteral(@"+) {
                            $('select[data-options]').append(`<option value=""${index_ + 1}"">${index_ + 1}</option>`);
                        }
                        $('select[data-options]').val(index);
                        stateManager();
                    } else {
                        onMask(""错误"", json.message);
                    }
                },
                error: function (jqXHR, textStatus, errorThrown) {
                    onMask(""错误"", ""网络接连错误.."");
                }
            });
        }

        $('.Next').click(function (jqEvent) {
            loadPageByIndex(parseInt($('.show-page-Index').text().trim()) + 1);
        });

        $('.First').click(function (jqEvent) {
            loadPageByIndex(1);
        });

        $('.Previous').click(function (jqEvent) {
            loadPageByIndex(parseInt($('.show-page-Index').text().trim()) - 1);
        });

        $('.Last').click(function (jqEvent) {
            loadPageByIndex($('button[data-la");
                WriteLiteral(@"stIndex]').attr(""data-lastIndex"").trim());
        });

        $('button[data-skip]').click(function (jqEvent) {
            var pageIndex = parseInt($('.show-page-Index').text().trim());
            var skip = parseInt($('select[data-options]').val().trim());
            if (skip === pageIndex) {
                onMask(""提示信息"", ""跳转页面为当前页面"");
            } else {
                loadPageByIndex($('select[data-options]').val());
            }
        });

        $('#search-items').click(function (jqEvent) {
            loadPageByIndex(1);
        });

        $('.section-items').on('click',
            '.detail-dialog',
            null,
            function (jqEvent) {
                $('#detail-dialog .update-form').attr(""data-item-id"", $(this).attr(""data-item-id""));

                var context = $(this).parents('tr').find("".item-content"").text();
                $('.update-form #contextText').val(context);
                $('.update-form #answerRe').val($(this).attr(""data-answer"")");
                WriteLiteral(@");

                $('#detail-dialog').modal('show');
            });

        $('.section-items').on('click',
            '.delete-dialog',
            null,
            function (jqEvent) {
                $('#delete-dialog button:eq(1)').attr(""data-item-id"", $(this).attr(""data-item-id""));
                $('#delete-dialog').modal('show');
            });

        $('#delete-dialog button:eq(1)').click(function(jqEvent) {
            var id = $(this).attr(""data-item-id"");
            $.ajax({
                url: ""/Judge/Delete"",
                type: ""post"",
                dataType: ""json"",
                data: {
                    judgeId: id
                },
                success: function (json, textStatus, jqXhr) {
                    console.log(json);
                    if (json.isOk) {
                        onMask(json.title, json.message);
                        loadPageByIndex(1);
                    } else {
                        onMask(json.title, json.m");
                WriteLiteral(@"essage);
                    }
                },
                error: function(jqXHR, textStatus, errorThrown) {
                    onMask(""错误"", ""网络接连错误.."");
                }});
        });

        $("".update-form"").validate({
            //错误提示信息
            messages: {
                contextText: {
                    required: ""请填写题干"",
                    minlength: ""题目允许的最小长度为{0}""
                },
                answerRe: {
                    required: ""请填写你的答案""
                }
            },
            //验证规则
            rules: {
                //使用空间 name 名称
                contextText: {
                    required: true,
                    minlength: 5
                },
                answerRe: {
                    required: true
                }
            },
            errorClass: ""text-primary"",
            submitHandler: function (form) {
                $.ajax({
                    url: ""/Judge/Update"",
                    type: ""post"",
  ");
                WriteLiteral(@"                  dataType: ""json"",
                    data: {
                        judgeId: $(form).attr(""data-item-id""),
                        content: $('#contextText').val(),
                        answer: $(""#answerRe"").val()
                    },
                    success: function (json, textStatus, jqXhr) {
                        //debug
                        console.log(json);

                        //end debug
                        if (json.isOk) {
                            form.reset();
                            loadPageByIndex(1);
                            onMask(json.title, json.message);
                        } else {
                            onMask(json.title, json.message);
                        }
                    },
                    error: function (jqXHR, textStatus, errorThrown) {
                        onMask(""错误"", ""网络连接失败..."");
                    }
                });
            }
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
