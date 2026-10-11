package server

import (
	"fmt"
	"strings"
)

// renderOpenAPI 生成 OpenAPI 3.0 规范（YAML）
// 手工维护以保持零依赖；路由新增时同步更新此文件。
func renderOpenAPI(base string) string {
	var b strings.Builder
	w := func(format string, a ...any) { fmt.Fprintf(&b, format+"\n", a...) }

	w("openapi: 3.0.3")
	w("info:")
	w("  title: PENTIGENT API")
	w("  description: AI 渗透测试系统 REST API（双图 + planner/worker 闭环）")
	w("  version: 0.1.0")
	w("servers:")
	w("  - url: %s", base)
	w("components:")
	w("  securitySchemes:")
	w("    bearerAuth:")
	w("      type: http")
	w("      scheme: bearer")
	w("      bearerFormat: JWT")
	w("  schemas:")
	w("    Error:")
	w("      type: object")
	w("      properties:")
	w("        error: { type: string }")

	// 通用操作生成
	op := func(tag, method, path, summary string, secured bool, params ...string) {
		w("  /%s:", strings.TrimPrefix(path, "/"))
		w("    %s:", method)
		w("      tags: [%s]", tag)
		w("      summary: %s", summary)
		if secured {
			w("      security: [{ bearerAuth: [] }]")
		}
		if len(params) > 0 {
			w("      parameters:")
			for _, p := range params {
				w("        - in: %s", p)
				w("          schema: { type: string }")
			}
		}
	}

	w("paths:")
	op("health", "get", "api/health", "健康检查（含 DB/LLM 可观测性）", false)
	op("auth", "post", "api/auth/setup", "首次设置管理员密码", false)
	op("auth", "post", "api/auth/login", "登录获取 JWT", false)
	op("llm", "post", "api/llm/test", "LLM 连通性探测", false)

	op("tasks", "get", "api/tasks", "任务列表（分页/状态/搜索）", true, "query status", "query q", "query limit", "query offset")
	op("tasks", "post", "api/tasks", "创建任务", true)
	op("tasks", "get", "api/stats", "全局统计", true)
	op("tasks", "get", "api/tasks/{id}", "任务详情", true)
	op("tasks", "delete", "api/tasks/{id}", "删除任务（级联清理）", true)
	op("tasks", "post", "api/tasks/{id}/start", "启动任务", true)
	op("tasks", "post", "api/tasks/{id}/pause", "暂停任务（可断点续跑）", true)
	op("tasks", "post", "api/tasks/{id}/stop", "停止任务", true)
	op("tasks", "post", "api/tasks/{id}/notes", "设置任务备注", true)
	op("tasks", "post", "api/tasks/{id}/clone", "复制任务为新一轮", true)
	op("tasks", "get", "api/tasks/{id}/events", "SSE 活动流", true)
	op("tasks", "get", "api/tasks/{id}/graph", "探索图（节点/边）", true)
	op("tasks", "get", "api/tasks/{id}/report", "任务报告（json/markdown）", true, "query format")
	op("tasks", "get", "api/tasks/{id}/history", "任务运行历史", true)
	op("tasks", "post", "api/reset", "清空演示数据（confirm=RESET）", true)

	op("assets", "get", "api/assets", "资产列表（分页/过滤）", true, "query type", "query q", "query limit", "query offset")
	op("assets", "get", "api/assets/{id}/coverage", "资产测试覆盖", true)
	op("export", "get", "api/export/assets.csv", "导出资产 CSV", true)
	op("export", "get", "api/export/findings.csv", "导出漏洞 CSV", true)

	op("findings", "get", "api/findings", "漏洞列表（分页/过滤）", true, "query severity", "query status", "query task")
	op("findings", "get", "api/findings/{id}", "漏洞详情（含证据链）", true)
	op("findings", "post", "api/findings/{id}/status", "设置漏洞状态（确认/误报）", true)
	op("findings", "delete", "api/findings/{id}", "删除漏洞", true)

	op("search", "get", "api/search", "全局搜索（任务/资产/漏洞）", true, "query q")

	op("templates", "get", "api/templates", "任务模板列表", true)
	op("templates", "post", "api/templates", "创建自定义模板", true)
	op("templates", "delete", "api/templates/{id}", "删除自定义模板（内置不可删）", true)
	op("report", "get", "api/report-settings", "获取报告设置", true)
	op("report", "post", "api/report-settings", "更新报告设置", true)

	op("intercept", "get", "api/intercept/pending", "待审批队列", true)
	op("intercept", "get", "api/intercept/rules", "审批规则列表", true)
	op("intercept", "post", "api/intercept/rules", "新增审批规则", true)
	op("intercept", "delete", "api/intercept/rules/{id}", "删除审批规则", true)
	op("intercept", "post", "api/intercept/{id}/decision", "审批决策（放行/拒绝）", true)

	return b.String()
}