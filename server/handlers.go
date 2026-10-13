package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"pentigent/db"
)

// ---- 任务 handlers 已拆分到 handlers_task.go ----

// ---- 资产 / 发现 / 公司 ----

func (s *Server) handleListAssets(w http.ResponseWriter, r *http.Request, _ map[string]string) {
	q := r.URL.Query()
	var companyID *int64
	if c := q.Get("company"); c != "" {
		if v, err := strconv.ParseInt(c, 10, 64); err == nil {
			companyID = &v
		}
	}
	typ := q.Get("type")
	search := q.Get("q")
	limit := parseIntParam(q.Get("limit"), 50, 1000)
	offset := parseIntParam(q.Get("offset"), 0, 100000)
	assets, total, err := s.db.SearchAssets(s.ctx(), companyID, typ, search, limit, offset)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if assets == nil {
		assets = []db.Asset{}
	}
	writeJSON(w, 200, map[string]any{"assets": assets, "total": total, "limit": limit, "offset": offset})
}

func (s *Server) handleListFindings(w http.ResponseWriter, r *http.Request, _ map[string]string) {
	q := r.URL.Query()
	var taskID *int64
	if t := q.Get("task"); t != "" {
		if v, err := strconv.ParseInt(t, 10, 64); err == nil {
			taskID = &v
		}
	}
	limit := parseIntParam(q.Get("limit"), 50, 1000)
	offset := parseIntParam(q.Get("offset"), 0, 100000)
	findings, total, err := s.db.ListFindings(s.ctx(), taskID, q.Get("severity"), q.Get("status"), limit, offset)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if findings == nil {
		findings = []db.Finding{}
	}
	writeJSON(w, 200, map[string]any{"findings": findings, "total": total, "limit": limit, "offset": offset})
}

func (s *Server) handleListCompanies(w http.ResponseWriter, r *http.Request, _ map[string]string) {
	companies, err := s.db.ListCompanies(s.ctx())
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"companies": companies})
}

// ---- 审批 ----

func (s *Server) handlePendingList(w http.ResponseWriter, r *http.Request, _ map[string]string) {
	status := r.URL.Query().Get("status")
	if status == "" {
		status = "pending"
	}
	pending, err := s.db.ListPending(s.ctx(), status, 200)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if pending == nil {
		pending = []db.PendingIntercept{}
	}
	writeJSON(w, 200, map[string]any{"pending": pending})
}

func (s *Server) handleRulesList(w http.ResponseWriter, r *http.Request, _ map[string]string) {
	rules, err := s.db.ListRules(s.ctx())
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"rules": rules})
}

func (s *Server) handleInterceptDecision(w http.ResponseWriter, r *http.Request, params map[string]string) {
	id, err := strconv.ParseInt(params["id"], 10, 64)
	if err != nil {
		writeErr(w, 400, "无效 id")
		return
	}
	var req struct {
		Approved bool `json:"approved"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, 400, "无效请求体")
		return
	}
	if err := s.db.DecidePending(s.ctx(), id, req.Approved); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	status := "denied"
	if req.Approved {
		status = "approved"
	}
	writeJSON(w, 200, map[string]any{"id": id, "status": status})
}

// parseIntParam 解析整数查询参数，非法/缺省用 def，超范围钳制到 [0, max]
func parseIntParam(s string, def, max int) int {
	if s == "" {
		return def
	}
	v, err := strconv.Atoi(s)
	if err != nil || v < 0 {
		return def
	}
	if v > max {
		return max
	}
	return v
}

// ---- 报告导出 ----

// handleAssetCoverage 单个资产的测试覆盖（被哪些 intent 测过、产出哪些 finding）
func (s *Server) handleAssetCoverage(w http.ResponseWriter, r *http.Request, params map[string]string) {
	id, err := strconv.ParseInt(params["id"], 10, 64)
	if err != nil {
		writeErr(w, 400, "无效 id")
		return
	}
	cov, err := s.db.AssetCoverage(s.ctx(), []int64{id})
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"coverage": cov})
}

// handleTaskReport 导出任务报告：?format=json (默认) | markdown
// 遵守全局报告设置：章节开关、漏洞严重性过滤、只含已确认
func (s *Server) handleTaskReport(w http.ResponseWriter, r *http.Request, params map[string]string) {
	id, err := parseID(r, params)
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	task, err := s.db.GetTask(s.ctx(), id)
	if err != nil {
		writeErr(w, 404, "任务不存在")
		return
	}
	// 报告设置（缺省兜底）
	settings, err := s.db.GetReportSettings(s.ctx())
	if err != nil {
		settings = &db.ReportSettings{ReportTitle: "渗透测试报告", MinSeverity: "info", ShowAssets: true, ShowCoverage: true}
	}
	scope, _ := s.db.ListScope(s.ctx(), id)
	explorationID, _ := s.db.ExplorationForTask(s.ctx(), id)
	nodes, _ := s.db.ListNodes(s.ctx(), explorationID, "", "")
	edges, _ := s.db.ListEdges(s.ctx(), explorationID)
	assets, _, _ := s.db.SearchAssets(s.ctx(), nil, "", "", 500, 0)

	// 按设置过滤漏洞（严重性 + 只含已确认）
	findings := filterFindings(s.db, s.ctx(), &id, settings)

	// 锚点覆盖
	var coverage []db.AssetCoverage
	if len(assets) > 0 {
		ids := make([]int64, len(assets))
		for i, a := range assets {
			ids[i] = a.ID
		}
		coverage, _ = s.db.AssetCoverage(s.ctx(), ids)
	}

	report := map[string]any{
		"task":        task,
		"scope":       scope,
		"nodes":       nodes,
		"edges":       edges,
		"assets":      assets,
		"coverage":    coverage,
		"findings":    findings,
		"settings":    settings,
		"generated_at": time.Now().Format(time.RFC3339),
	}

	if r.URL.Query().Get("format") == "markdown" {
		md := renderMarkdownReport(task, scope, findings, assets, coverage, nodes, settings)
		w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="report-task-%d.md"`, id))
		w.WriteHeader(200)
		_, _ = w.Write([]byte(md))
		return
	}
	writeJSON(w, 200, report)
}

// filterFindings 按报告设置过滤漏洞
func filterFindings(d *db.DB, ctx context.Context, taskID *int64, s *db.ReportSettings) []db.Finding {
	all, _, _ := d.ListFindings(ctx, taskID, "", "", 500, 0)
	sevRank := map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
	minRank, ok := sevRank[s.MinSeverity]
	if !ok {
		minRank = 4
	}
	out := []db.Finding{}
	for _, f := range all {
		if s.ConfirmedOnly && f.Status != "confirmed" {
			continue
		}
		r, ok := sevRank[f.Severity]
		if !ok {
			r = 4
		}
		if r <= minRank {
			out = append(out, f)
		}
	}
	return out
}

// renderMarkdownReport 渲染可交付的 Markdown 报告（遵守报告设置）
func renderMarkdownReport(task *db.Task, scope []db.ScopeItem, findings []db.Finding, assets []db.Asset, coverage []db.AssetCoverage, nodes []db.Node, settings *db.ReportSettings) string {
	var b strings.Builder
	sevRank := map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

	// 品牌抬头
	if settings.OrgName != "" {
		b.WriteString(fmt.Sprintf("**%s**\n\n", settings.OrgName))
	}
	if settings.LogoURL != "" {
		b.WriteString(fmt.Sprintf("![logo](%s)\n\n", settings.LogoURL))
	}
	title := settings.ReportTitle
	if title == "" {
		title = "渗透测试报告"
	}
	b.WriteString(fmt.Sprintf("# %s\n\n", title))
	b.WriteString(fmt.Sprintf("**任务**: %s\n\n", task.Name))
	b.WriteString(fmt.Sprintf("**状态**: %s\n\n", task.Status))
	b.WriteString(fmt.Sprintf("**目标**: %s\n\n", task.Goal))
	if task.Error != "" {
		b.WriteString(fmt.Sprintf("**错误**: %s\n\n", task.Error))
	}

	b.WriteString("## 授权范围\n\n")
	for _, s := range scope {
		b.WriteString(fmt.Sprintf("- `%s` (%s)\n", s.Pattern, s.Kind))
	}

	if settings.ShowAssets {
		b.WriteString("\n## 发现的资产\n\n")
		if len(assets) == 0 {
			b.WriteString("（无）\n\n")
		} else {
			b.WriteString("| ID | 类型 | 域名 | URL |\n|---|---|---|---|\n")
			for _, a := range assets {
				b.WriteString(fmt.Sprintf("| %d | %s | %s | %s |\n", a.ID, a.Type, a.Domain, a.URL))
			}
			b.WriteString("\n")
		}
	}

	if settings.ShowFacts {
		var facts []db.Node
		for _, n := range nodes {
			if n.Type == "fact" {
				facts = append(facts, n)
			}
		}
		b.WriteString("\n## 探测事实\n\n")
		if len(facts) == 0 {
			b.WriteString("（无）\n\n")
		} else {
			for _, f := range facts {
				b.WriteString(fmt.Sprintf("- %s\n", f.Title))
			}
			b.WriteString("\n")
		}
	}

	b.WriteString("\n## 漏洞发现\n\n")
	if len(findings) == 0 {
		b.WriteString("（无）\n\n")
	} else {
		sorted := make([]db.Finding, len(findings))
		copy(sorted, findings)
		for i := 1; i < len(sorted); i++ {
			for j := i; j > 0 && sevRank[sorted[j].Severity] < sevRank[sorted[j-1].Severity]; j-- {
				sorted[j], sorted[j-1] = sorted[j-1], sorted[j]
			}
		}
		for _, f := range sorted {
			sev := f.Severity
			if sev == "" {
				sev = "info"
			}
			b.WriteString(fmt.Sprintf("### [%s] %s\n\n", strings.ToUpper(sev), f.Title))
			if f.Evidence != nil {
				if u, ok := f.Evidence["url"].(string); ok && u != "" {
					b.WriteString(fmt.Sprintf("- 位置: `%s`\n", u))
				}
				if note, ok := f.Evidence["note"].(string); ok && note != "" {
					b.WriteString(fmt.Sprintf("- 说明: %s\n", note))
				}
			}
			if f.TaskName != "" {
				b.WriteString(fmt.Sprintf("- 来源任务: %s\n", f.TaskName))
			}
			b.WriteString("\n")
		}
	}

	if settings.ShowCoverage {
		b.WriteString("## 资产测试覆盖\n\n")
		if len(coverage) == 0 {
			b.WriteString("（无）\n\n")
		} else {
			for _, c := range coverage {
				b.WriteString(fmt.Sprintf("### `%s` (%s)\n\n", c.Domain, c.Type))
				if len(c.TestedBy) > 0 {
					b.WriteString("- 被意图测试:\n")
					for _, n := range c.TestedBy {
						b.WriteString(fmt.Sprintf("  - %s\n", n.Title))
					}
				}
				if len(c.Findings) > 0 {
					b.WriteString("- 相关发现:\n")
					for _, n := range c.Findings {
						b.WriteString(fmt.Sprintf("  - %s\n", n.Title))
					}
				}
				b.WriteString("\n")
			}
		}
	}

	b.WriteString("---\n")
	if settings.Footer != "" {
		b.WriteString(fmt.Sprintf("%s\n\n", settings.Footer))
	}
	b.WriteString(fmt.Sprintf("*由 PENTIGENT 生成 · %s*\n", time.Now().Format("2006-01-02 15:04")))
	return b.String()
}

// ---- 漏洞详情 ----

// handleGetFinding 单条漏洞详情（含证据链：资产 / 发现它的意图）
func (s *Server) handleGetFinding(w http.ResponseWriter, r *http.Request, params map[string]string) {
	id, err := strconv.ParseInt(params["id"], 10, 64)
	if err != nil {
		writeErr(w, 400, "无效 id")
		return
	}
	fd, err := s.db.GetFindingDetail(s.ctx(), id)
	if err != nil {
		writeErr(w, 404, "漏洞不存在")
		return
	}
	writeJSON(w, 200, fd)
}

// ---- 运行历史 ----

// handleTaskHistory 任务的所有运行历史
func (s *Server) handleTaskHistory(w http.ResponseWriter, r *http.Request, params map[string]string) {
	id, err := parseID(r, params)
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	hist, err := s.db.ListRunHistory(s.ctx(), id)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if hist == nil {
		hist = []db.RunHistoryItem{}
	}
	writeJSON(w, 200, map[string]any{"history": hist})
}

// ---- CSV 导出 ----

// csvEscape 转义 CSV 字段
func csvEscape(s string) string {
	if strings.ContainsAny(s, ",\"\n\r") {
		return `"` + strings.ReplaceAll(s, `"`, `""`) + `"`
	}
	return s
}

func writeCSVHeaders(w http.ResponseWriter, filename string) {
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="`+filename+`"`)
	// BOM 让 Excel 正确识别 UTF-8
	w.Write([]byte{0xEF, 0xBB, 0xBF})
}

func (s *Server) handleExportAssetsCSV(w http.ResponseWriter, r *http.Request, _ map[string]string) {
	q := r.URL.Query()
	var companyID *int64
	if c := q.Get("company"); c != "" {
		if v, err := strconv.ParseInt(c, 10, 64); err == nil {
			companyID = &v
		}
	}
	assets, _, err := s.db.SearchAssets(s.ctx(), companyID, q.Get("type"), q.Get("q"), 10000, 0)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeCSVHeaders(w, "assets.csv")
	_, _ = fmt.Fprintln(w, "ID,类型,域名,URL,标题")
	for _, a := range assets {
		_, _ = fmt.Fprintf(w, "%d,%s,%s,%s,%s\n",
			a.ID, csvEscape(a.Type), csvEscape(a.Domain), csvEscape(a.URL), csvEscape(a.Title))
	}
}

func (s *Server) handleExportFindingsCSV(w http.ResponseWriter, r *http.Request, _ map[string]string) {
	q := r.URL.Query()
	var taskID *int64
	if t := q.Get("task"); t != "" {
		if v, err := strconv.ParseInt(t, 10, 64); err == nil {
			taskID = &v
		}
	}
	findings, _, err := s.db.ListFindings(s.ctx(), taskID, q.Get("severity"), q.Get("status"), 10000, 0)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeCSVHeaders(w, "findings.csv")
	_, _ = fmt.Fprintln(w, "ID,项目,严重性,状态,标题,证据,发现时间")
	for _, f := range findings {
		ev := ""
		if f.Evidence != nil {
			if u, ok := f.Evidence["url"].(string); ok {
				ev = u
			}
		}
		_, _ = fmt.Fprintf(w, "%d,%s,%s,%s,%s,%s,%s\n",
			f.ID, csvEscape(f.TaskName), csvEscape(f.Severity), csvEscape(f.Status),
			csvEscape(f.Title), csvEscape(ev), csvEscape(f.CreatedAt))
	}
}

// ---- 全局搜索 ----

// handleGlobalSearch 跨任务/资产/漏洞的统一搜索
func (s *Server) handleGlobalSearch(w http.ResponseWriter, r *http.Request, _ map[string]string) {
	q := r.URL.Query().Get("q")
	if strings.TrimSpace(q) == "" {
		writeJSON(w, 200, map[string]any{"tasks": []any{}, "assets": []any{}, "findings": []any{}})
		return
	}
	tasks, _, _ := s.db.ListTasks(s.ctx(), "", q, 10, 0)
	assets, _, _ := s.db.SearchAssets(s.ctx(), nil, "", q, 10, 0)
	findings, _ := s.db.SearchFindings(s.ctx(), q, 10)
	if tasks == nil {
		tasks = []db.Task{}
	}
	if assets == nil {
		assets = []db.Asset{}
	}
	if findings == nil {
		findings = []db.Finding{}
	}
	writeJSON(w, 200, map[string]any{"tasks": tasks, "assets": assets, "findings": findings})
}

// ---- 模板 / 报告设置 / API 文档 ----

func (s *Server) handleListTemplates(w http.ResponseWriter, r *http.Request, _ map[string]string) {
	templates, err := s.db.ListTaskTemplates(s.ctx())
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if templates == nil {
		templates = []db.TaskTemplate{}
	}
	writeJSON(w, 200, map[string]any{"templates": templates})
}

func (s *Server) handleCreateTemplate(w http.ResponseWriter, r *http.Request, _ map[string]string) {
	var t db.TaskTemplate
	if err := json.NewDecoder(r.Body).Decode(&t); err != nil {
		writeErr(w, 400, "无效请求体")
		return
	}
	if t.Name == "" || t.Goal == "" {
		writeErr(w, 400, "name 和 goal 必填")
		return
	}
	t.Builtin = false
	id, err := s.db.CreateTaskTemplate(s.ctx(), t)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"id": id, "created": true})
}

func (s *Server) handleDeleteTemplate(w http.ResponseWriter, r *http.Request, params map[string]string) {
	id, err := strconv.ParseInt(params["id"], 10, 64)
	if err != nil {
		writeErr(w, 400, "无效 id")
		return
	}
	if err := s.db.DeleteTaskTemplate(s.ctx(), id); err != nil {
		// 内置模板 / 不存在 → 400 明确报错，而不是静默 200
		writeErr(w, 400, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"deleted": id})
}

func (s *Server) handleGetReportSettings(w http.ResponseWriter, r *http.Request, _ map[string]string) {
	rs, err := s.db.GetReportSettings(s.ctx())
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, rs)
}

func (s *Server) handleUpdateReportSettings(w http.ResponseWriter, r *http.Request, _ map[string]string) {
	var rs db.ReportSettings
	if err := json.NewDecoder(r.Body).Decode(&rs); err != nil {
		writeErr(w, 400, "无效请求体")
		return
	}
	if err := s.db.UpdateReportSettings(s.ctx(), rs); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, rs)
}

// handleOpenAPI 提供 OpenAPI 3 规范（yaml 文本）
func (s *Server) handleOpenAPI(w http.ResponseWriter, r *http.Request, _ map[string]string) {
	base := "http://" + r.Host
	w.Header().Set("Content-Type", "application/yaml; charset=utf-8")
	_, _ = w.Write([]byte(renderOpenAPI(base)))
}

// handleFindingStatus 更新漏洞状态（confirmed / dismissed 误报）
func (s *Server) handleFindingStatus(w http.ResponseWriter, r *http.Request, params map[string]string) {
	id, err := strconv.ParseInt(params["id"], 10, 64)
	if err != nil {
		writeErr(w, 400, "无效 id")
		return
	}
	var req struct {
		Status string `json:"status"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, 400, "无效请求体")
		return
	}
	if req.Status != "confirmed" && req.Status != "dismissed" {
		writeErr(w, 400, "status 必须是 confirmed 或 dismissed")
		return
	}
	if err := s.db.SetFindingStatus(s.ctx(), id, req.Status); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"id": id, "status": req.Status})
}

// handleDeleteFinding 删除单个漏洞
func (s *Server) handleDeleteFinding(w http.ResponseWriter, r *http.Request, params map[string]string) {
	id, err := strconv.ParseInt(params["id"], 10, 64)
	if err != nil {
		writeErr(w, 400, "无效 id")
		return
	}
	if err := s.db.DeleteFinding(s.ctx(), id); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"deleted": id})
}

// handleCreateRule 新增审批规则
func (s *Server) handleCreateRule(w http.ResponseWriter, r *http.Request, _ map[string]string) {
	var rule db.InterceptRule
	if err := json.NewDecoder(r.Body).Decode(&rule); err != nil {
		writeErr(w, 400, "无效请求体")
		return
	}
	if rule.Name == "" || rule.Pattern == "" {
		writeErr(w, 400, "name 和 pattern 必填")
		return
	}
	if rule.MatchTarget == "" {
		rule.MatchTarget = "tool_name"
	}
	if rule.MatchType == "" {
		rule.MatchType = "string"
	}
	if rule.Action == "" {
		rule.Action = "deny"
	}
	if rule.Priority == 0 {
		rule.Priority = 100
	}
	id, err := s.db.CreateRule(s.ctx(), rule)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"id": id, "created": true})
}

// handleDeleteRule 删除审批规则
func (s *Server) handleDeleteRule(w http.ResponseWriter, r *http.Request, params map[string]string) {
	id, err := strconv.ParseInt(params["id"], 10, 64)
	if err != nil {
		writeErr(w, 400, "无效 id")
		return
	}
	if err := s.db.DeleteRule(s.ctx(), id); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"deleted": id})
}

// isIP 判断是否 IP
func isIP(s string) bool {
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return false
	}
	for _, p := range parts {
		n := 0
		for _, c := range p {
			if c < '0' || c > '9' {
				return false
			}
			n = n*10 + int(c-'0')
		}
		if n > 255 {
			return false
		}
	}
	return true
}