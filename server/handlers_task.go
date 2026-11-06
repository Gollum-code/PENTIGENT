package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"pentigent/db"
)

// ---- 任务 handlers ----

func (s *Server) handleStats(w http.ResponseWriter, r *http.Request, _ map[string]string) {
	stats, err := s.db.GetStats(r.Context())
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
	tasks, total, err := s.db.ListTasks(r.Context(), q.Get("status"), q.Get("q"), limit, offset)
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
	companyID, err := s.db.EnsureCompany(r.Context(), "default")
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	cid := companyID
	taskID, err := s.db.CreateTask(r.Context(), req.Name, req.Goal, req.Description, &cid)
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
		_ = s.db.AddScope(r.Context(), taskID, host, kind)
	}

	// 校验：目标里提到的域名若不在授权范围内，给出警告（否则任务会全程被硬边界拦截）
	scopeSet := map[string]bool{}
	for _, sc := range req.Scope {
		scopeSet[strings.ToLower(sc)] = true
	}
	var warnings []string
	if len(req.Scope) == 0 {
		warnings = append(warnings, "未能从目标描述中识别出授权域名/IP，范围为空将导致所有探测被硬边界拦截，请手动填写授权范围")
	}
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
	if err := s.db.SetTaskNotes(r.Context(), id, req.Notes); err != nil {
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
	task, err := s.db.GetTask(r.Context(), id)
	if err != nil {
		writeErr(w, 404, "任务不存在")
		return
	}
	scope, _ := s.db.ListScope(r.Context(), id)
	findings, _, _ := s.db.ListFindings(r.Context(), &id, "", "", 100, 0)
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
	if err := s.db.DeleteTask(r.Context(), id); err != nil {
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
	task, err := s.db.GetTask(r.Context(), id)
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
	_ = s.db.SetExplorationStatusForTask(r.Context(), id, "paused")
	_ = s.db.SetTaskStatus(r.Context(), id, "paused", "")
	writeJSON(w, 200, map[string]any{"id": id, "status": "paused"})
}

func (s *Server) handleStopTask(w http.ResponseWriter, r *http.Request, params map[string]string) {
	id, err := parseID(r, params)
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	s.engine.Stop(id)
	_ = s.db.SetTaskStatus(r.Context(), id, "stopped", "")
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

	// 先订阅，再补推历史/断线期间的事件，避免订阅瞬间遗漏。
	// 每个任务只有一个 DB 轮询 goroutine（sseHub），客户端数增加不放大查询。
	ch, unsubscribe := s.sse.subscribe(id)
	defer unsubscribe()

	writeEvent := func(a db.Activity) bool {
		b, _ := json.Marshal(a)
		_, err := fmt.Fprintf(w, "id: %d\ndata: %s\n\n", a.ID, string(b))
		return err == nil
	}

	// 断线重连：浏览器会带 Last-Event-ID；也支持 ?lastEventId= 便于调试。
	var lastID int64
	if v := r.Header.Get("Last-Event-ID"); v != "" {
		lastID, _ = strconv.ParseInt(v, 10, 64)
	} else if v := r.URL.Query().Get("lastEventId"); v != "" {
		lastID, _ = strconv.ParseInt(v, 10, 64)
	}
	var initial []db.Activity
	if lastID > 0 {
		initial, _ = s.db.ListActivityAfter(r.Context(), id, lastID, 200)
	} else {
		initial, _ = s.db.ListRecentActivity(r.Context(), id, 50)
	}
	for _, a := range initial {
		if !writeEvent(a) {
			return
		}
	}
	flusher.Flush()

	// 心跳只写注释行，不查库
	heartbeat := time.NewTicker(15 * time.Second)
	defer heartbeat.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case a := <-ch:
			if !writeEvent(a) {
				return
			}
			flusher.Flush()
		case <-heartbeat.C:
			if _, err := fmt.Fprint(w, ": ping\n\n"); err != nil {
				return
			}
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
	explorationID, err := s.db.ExplorationForTask(r.Context(), id)
	if err != nil {
		writeJSON(w, 200, map[string]any{"nodes": []any{}, "edges": []any{}})
		return
	}
	nodes, _ := s.db.ListNodes(r.Context(), explorationID, "", "")
	edges, _ := s.db.ListEdges(r.Context(), explorationID)
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
	newID, err := s.db.CloneTask(r.Context(), id, req.Name, req.Goal)
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
	if err := s.db.ResetAllData(r.Context()); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"reset": true})
}
