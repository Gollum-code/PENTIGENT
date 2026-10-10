package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"artex/db"
)

// ---- 任务 ----

func (s *Server) handleStats(w http.ResponseWriter, r *http.Request, _ map[string]string) {
	stats, err := s.db.GetStats(s.ctx())
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, stats)
}

func (s *Server) handleListTasks(w http.ResponseWriter, r *http.Request, _ map[string]string) {
	q := r.URL.Query()
	limit := parseIntParam(q.Get("limit"), 50, 200)
	offset := parseIntParam(q.Get("offset"), 0, 100000)
	tasks, total, err := s.db.ListTasks(s.ctx(), q.Get("status"), q.Get("q"), limit, offset)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if tasks == nil {
		tasks = []db.Task{}
	}
	writeJSON(w, 200, map[string]any{"tasks": tasks, "total": total, "limit": limit, "offset": offset})
}

func (s *Server) handleCreateTask(w http.ResponseWriter, r *http.Request, _ map[string]string) {
	var req struct {
		Name        string   `json:"name"`
		Goal        string   `json:"goal"`
		Description string   `json:"description"`
		Scope       []string `json:"scope"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, 400, "无效请求体")
		return
	}
	if req.Goal == "" {
		writeErr(w, 400, "goal 不能为空")
		return
	}
	if req.Name == "" {
		req.Name = req.Goal
	}

	// 确保默认公司（资产全局真值库归属）
	companyID, err := s.db.EnsureCompany(s.ctx(), "default")
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	cid := companyID
	taskID, err := s.db.CreateTask(s.ctx(), req.Name, req.Goal, req.Description, &cid)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	// 授权边界（覆盖度分母 / 硬边界依据）
	if len(req.Scope) == 0 {
		req.Scope = extractDomains(req.Goal + " " + req.Description)
	}
	for _, host := range req.Scope {
		kind := "domain"
		if strings.Contains(host, "/") {
			kind = "url_prefix"
		} else if isIP(host) {
			kind = "ip"
		}
		_ = s.db.AddScope(s.ctx(), taskID, host, kind)
	}
	writeJSON(w, 200, map[string]any{"id": taskID, "name": req.Name, "goal": req.Goal, "status": "created"})
}

func (s *Server) handleSetTaskNotes(w http.ResponseWriter, r *http.Request, params map[string]string) {
	id, err := parseID(r, params)
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	var req struct {
		Notes string `json:"notes"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, 400, "无效请求体")
		return
	}
	if err := s.db.SetTaskNotes(s.ctx(), id, req.Notes); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"id": id, "notes": req.Notes})
}

func (s *Server) handleGetTask(w http.ResponseWriter, r *http.Request, params map[string]string) {
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
	scope, _ := s.db.ListScope(s.ctx(), id)
	findings, _, _ := s.db.ListFindings(s.ctx(), &id, "", "", 100, 0)
	writeJSON(w, 200, map[string]any{
		"task":     task,
		"scope":    scope,
		"findings": findings,
		"running":  s.engine.IsRunning(id),
	})
}

func (s *Server) handleDeleteTask(w http.ResponseWriter, r *http.Request, params map[string]string) {
	id, err := parseID(r, params)
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	s.engine.Stop(id)
	if err := s.db.DeleteTask(s.ctx(), id); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"deleted": id})
}

func (s *Server) handleStartTask(w http.ResponseWriter, r *http.Request, params map[string]string) {
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
	// 真正在跑才拒绝；僵尸 running（进程崩溃遗留）允许重启恢复
	if task.Status == "running" && s.engine.IsRunning(id) {
		writeErr(w, 400, "任务已在运行")
		return
	}
	if err := s.engine.Start(id); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"id": id, "status": "running"})
}

func (s *Server) handlePauseTask(w http.ResponseWriter, r *http.Request, params map[string]string) {
	id, err := parseID(r, params)
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	s.engine.Stop(id)
	// 保留探索状态为 paused，供下次 start 断点续跑
	_ = s.db.SetExplorationStatusForTask(s.ctx(), id, "paused")
	_ = s.db.SetTaskStatus(s.ctx(), id, "paused", "")
	writeJSON(w, 200, map[string]any{"id": id, "status": "paused"})
}

func (s *Server) handleStopTask(w http.ResponseWriter, r *http.Request, params map[string]string) {
	id, err := parseID(r, params)
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	s.engine.Stop(id)
	_ = s.db.SetTaskStatus(s.ctx(), id, "stopped", "")
	writeJSON(w, 200, map[string]any{"id": id, "status": "stopped"})
}

// ---- SSE 活动流 ----

func (s *Server) handleTaskEvents(w http.ResponseWriter, r *http.Request, params map[string]string) {
	id, err := parseID(r, params)
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeErr(w, 500, "不支持流式")
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(200)

	var lastID int64
	// 首次立即推送最近活动
	if rows, err := s.db.ListActivityAfter(s.ctx(), id, 0, 50); err == nil && len(rows) > 0 {
		for _, a := range rows {
			b, _ := json.Marshal(a)
			fmt.Fprintf(w, "data: %s\n\n", string(b))
			lastID = a.ID
		}
		flusher.Flush()
	}

	ticker := time.NewTicker(700 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-ticker.C:
			rows, err := s.db.ListActivityAfter(s.ctx(), id, lastID, 100)
			if err != nil {
				continue
			}
			for _, a := range rows {
				b, _ := json.Marshal(a)
				fmt.Fprintf(w, "data: %s\n\n", string(b))
				lastID = a.ID
			}
			if len(rows) > 0 {
				flusher.Flush()
			}
			// 心跳注释行，保持连接
			fmt.Fprintf(w, ": ping\n\n")
			flusher.Flush()
		}
	}
}

// ---- 探索图 ----

func (s *Server) handleTaskGraph(w http.ResponseWriter, r *http.Request, params map[string]string) {
	id, err := parseID(r, params)
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	// 找该任务的 exploration
	explorationID, err := s.db.ExplorationForTask(s.ctx(), id)
	if err != nil {
		writeJSON(w, 200, map[string]any{"nodes": []any{}, "edges": []any{}})
		return
	}
	nodes, _ := s.db.ListNodes(s.ctx(), explorationID, "", "")
	edges, _ := s.db.ListEdges(s.ctx(), explorationID)
	if nodes == nil {
		nodes = []db.Node{}
	}
	if edges == nil {
		edges = []db.Edge{}
	}
	writeJSON(w, 200, map[string]any{"exploration_id": explorationID, "nodes": nodes, "edges": edges})
}

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
	scope, _ := s.db.ListScope(s.ctx(), id)
	findings, _, _ := s.db.ListFindings(s.ctx(), &id, "", "", 500, 0)
	explorationID, _ := s.db.ExplorationForTask(s.ctx(), id)
	nodes, _ := s.db.ListNodes(s.ctx(), explorationID, "", "")
	edges, _ := s.db.ListEdges(s.ctx(), explorationID)
	assets, _, _ := s.db.SearchAssets(s.ctx(), nil, "", "", 500, 0)
	// 锚点覆盖（asset → 测过它的 intent / finding）
	var coverage []db.AssetCoverage
	if len(assets) > 0 {
		ids := make([]int64, len(assets))
		for i, a := range assets {
			ids[i] = a.ID
		}
		coverage, _ = s.db.AssetCoverage(s.ctx(), ids)
	}

	report := map[string]any{
		"task":     task,
		"scope":    scope,
		"nodes":    nodes,
		"edges":    edges,
		"assets":   assets,
		"coverage": coverage,
		"findings": findings,
		"generated_at": time.Now().Format(time.RFC3339),
	}

	if r.URL.Query().Get("format") == "markdown" {
		md := renderMarkdownReport(task, scope, findings, assets, coverage)
		w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="report-task-%d.md"`, id))
		w.WriteHeader(200)
		_, _ = w.Write([]byte(md))
		return
	}
	writeJSON(w, 200, report)
}

// renderMarkdownReport 把任务成果渲染成可交付的 Markdown 报告
func renderMarkdownReport(task *db.Task, scope []db.ScopeItem, findings []db.Finding, assets []db.Asset, coverage []db.AssetCoverage) string {
	var b strings.Builder
	sevRank := map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

	b.WriteString(fmt.Sprintf("# 渗透测试报告\n\n"))
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

	b.WriteString("## 漏洞发现\n\n")
	if len(findings) == 0 {
		b.WriteString("（无）\n\n")
	} else {
		// 按严重性排序
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
			url := ""
			if f.Evidence != nil {
				if u, ok := f.Evidence["url"].(string); ok {
					url = u
				}
				if note, ok := f.Evidence["note"].(string); ok && note != "" {
					b.WriteString(fmt.Sprintf("- 说明: %s\n", note))
				}
			}
			if url != "" {
				b.WriteString(fmt.Sprintf("- 位置: `%s`\n", url))
			}
			b.WriteString("\n")
		}
	}

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

	b.WriteString(fmt.Sprintf("---\n*由 PENTIGENT 生成 · %s*\n", time.Now().Format("2006-01-02 15:04")))
	return b.String()
}

// ---- 新增端点 ----

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

// handleCloneTask 复制任务为新一轮
func (s *Server) handleCloneTask(w http.ResponseWriter, r *http.Request, params map[string]string) {
	id, err := parseID(r, params)
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	var req struct {
		Name string `json:"name"`
		Goal string `json:"goal"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req) // body 可为空
	newID, err := s.db.CloneTask(s.ctx(), id, req.Name, req.Goal)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"id": newID, "cloned_from": id})
}

// handleResetData 清空演示数据（危险操作，仅本地）
func (s *Server) handleResetData(w http.ResponseWriter, r *http.Request, _ map[string]string) {
	var req struct {
		Confirm string `json:"confirm"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Confirm != "RESET" {
		writeErr(w, 400, "需要 confirm=RESET 以确认清空全部数据")
		return
	}
	if err := s.db.ResetAllData(s.ctx()); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"reset": true})
}

// isIP 判断是否 IP
func isIP(s string) bool {	parts := strings.Split(s, ".")
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