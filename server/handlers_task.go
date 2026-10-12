package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"pentigent/db"
)

// ---- 任务 handlers ----

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

	// 校验：目标里提到的域名若不在授权范围内，给出警告（否则任务会全程被硬边界拦截）
	scopeSet := map[string]bool{}
	for _, sc := range req.Scope {
		scopeSet[strings.ToLower(sc)] = true
	}
	var warnings []string
	mentioned := extractDomains(req.Goal + " " + req.Description)
	for _, h := range mentioned {
		lh := strings.ToLower(h)
		inScope := false
		for sc := range scopeSet {
			if lh == sc || strings.HasSuffix(lh, "."+sc) {
				inScope = true
				break
			}
		}
		if !inScope {
			warnings = append(warnings, h+" 在目标描述里但不在授权范围，相关探测会被硬边界拦截")
		}
	}

	writeJSON(w, 200, map[string]any{
		"id": taskID, "name": req.Name, "goal": req.Goal, "status": "created",
		"scope": req.Scope, "warnings": warnings,
	})
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

// ---- 复制 / 重置 ----

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