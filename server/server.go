package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"artex/agent"
	"artex/config"
	"artex/db"

	"github.com/golang-jwt/jwt/v5"
)

type Server struct {
	cfg    *config.Config
	db     *db.DB
	engine *Engine
	// serveStatic 由 cmd 注入（go:embed 前端）
	serveStatic http.Handler
}

// 简易路由表：method + path pattern
type route struct {
	Method  string
	Pattern string // 例如 /api/tasks/:id
	Handler func(w http.ResponseWriter, r *http.Request, params map[string]string)
	Auth    bool
}

func NewServer(cfg *config.Config, database *db.DB) *Server {
	engine := NewEngine(database, cfg.Agent.Workers)
	return &Server{cfg: cfg, db: database, engine: engine}
}

func (s *Server) Engine() *Engine { return s.engine }

// router 注册路由
func (s *Server) routes() []route {
	return []route{
		// 健康检查（免认证）
		{Method: "GET", Pattern: "/api/health", Handler: s.handleHealth, Auth: false},

		// 认证
		{Method: "POST", Pattern: "/api/auth/setup", Handler: s.handleSetup, Auth: false},
		{Method: "POST", Pattern: "/api/auth/login", Handler: s.handleLogin, Auth: false},
		{Method: "POST", Pattern: "/api/llm/test", Handler: s.handleLLMTest, Auth: false},

		// 任务
		{Method: "GET", Pattern: "/api/tasks", Handler: s.handleListTasks, Auth: true},
		{Method: "GET", Pattern: "/api/stats", Handler: s.handleStats, Auth: true},
		{Method: "POST", Pattern: "/api/tasks", Handler: s.handleCreateTask, Auth: true},
		{Method: "GET", Pattern: "/api/tasks/:id", Handler: s.handleGetTask, Auth: true},
		{Method: "DELETE", Pattern: "/api/tasks/:id", Handler: s.handleDeleteTask, Auth: true},
		{Method: "POST", Pattern: "/api/tasks/:id/start", Handler: s.handleStartTask, Auth: true},
		{Method: "POST", Pattern: "/api/tasks/:id/pause", Handler: s.handlePauseTask, Auth: true},
		{Method: "POST", Pattern: "/api/tasks/:id/stop", Handler: s.handleStopTask, Auth: true},
		{Method: "POST", Pattern: "/api/tasks/:id/notes", Handler: s.handleSetTaskNotes, Auth: true},
		{Method: "POST", Pattern: "/api/tasks/:id/clone", Handler: s.handleCloneTask, Auth: true},
		{Method: "GET", Pattern: "/api/tasks/:id/events", Handler: s.handleTaskEvents, Auth: true}, // SSE
		{Method: "GET", Pattern: "/api/tasks/:id/graph", Handler: s.handleTaskGraph, Auth: true},
		{Method: "POST", Pattern: "/api/reset", Handler: s.handleResetData, Auth: true},

		// 资产 / 发现
		{Method: "GET", Pattern: "/api/assets", Handler: s.handleListAssets, Auth: true},
		{Method: "GET", Pattern: "/api/assets/:id/coverage", Handler: s.handleAssetCoverage, Auth: true},
		{Method: "GET", Pattern: "/api/findings", Handler: s.handleListFindings, Auth: true},
		{Method: "POST", Pattern: "/api/findings/:id/status", Handler: s.handleFindingStatus, Auth: true},
		{Method: "DELETE", Pattern: "/api/findings/:id", Handler: s.handleDeleteFinding, Auth: true},
		{Method: "GET", Pattern: "/api/companies", Handler: s.handleListCompanies, Auth: true},
		{Method: "GET", Pattern: "/api/tasks/:id/report", Handler: s.handleTaskReport, Auth: true},

		// 审批
		{Method: "GET", Pattern: "/api/intercept/pending", Handler: s.handlePendingList, Auth: true},
		{Method: "GET", Pattern: "/api/intercept/rules", Handler: s.handleRulesList, Auth: true},
		{Method: "POST", Pattern: "/api/intercept/rules", Handler: s.handleCreateRule, Auth: true},
		{Method: "DELETE", Pattern: "/api/intercept/rules/:id", Handler: s.handleDeleteRule, Auth: true},
		{Method: "POST", Pattern: "/api/intercept/:id/decision", Handler: s.handleInterceptDecision, Auth: true},
	}
}

func (s *Server) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// CORS（开发期）
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET,POST,DELETE,OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type,Authorization")
		if r.Method == "OPTIONS" {
			w.WriteHeader(200)
			return
		}

		for _, rt := range s.routes() {
			if rt.Method != r.Method {
				continue
			}
			params, ok := matchPath(rt.Pattern, r.URL.Path)
			if !ok {
				continue
			}
			if rt.Auth && !s.cfg.Auth.Disabled {
				if !s.checkAuth(r) {
					writeErr(w, http.StatusUnauthorized, "未授权")
					return
				}
			}
			rt.Handler(w, r, params)
			return
		}
		// 静态资源兜底交给前端（若已内嵌）
		if s.serveStatic != nil {
			s.serveStatic.ServeHTTP(w, r)
			return
		}
		http.NotFound(w, r)
	})
}

// ---- 认证 ----

func (s *Server) hashPassword(password string) string {
	h := sha256.Sum256([]byte(password + s.cfg.Auth.JWTSecret))
	return hex.EncodeToString(h[:])
}

func (s *Server) isSetup() bool {
	var v []byte
	err := s.db.Pool().QueryRow(s.ctx(), `SELECT value FROM settings WHERE key='admin'`).Scan(&v)
	return err == nil && len(v) > 0
}

func (s *Server) handleSetup(w http.ResponseWriter, r *http.Request, _ map[string]string) {
	if s.isSetup() {
		writeErr(w, http.StatusBadRequest, "已完成初始设置")
		return
	}
	var req struct {
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Password == "" {
		writeErr(w, http.StatusBadRequest, "无效请求")
		return
	}
	pwHash := s.hashPassword(req.Password)
	_, err := s.db.Pool().Exec(s.ctx(),
		`INSERT INTO settings (key, value) VALUES ('admin', $1::jsonb) ON CONFLICT (key) DO UPDATE SET value=EXCLUDED.value`,
		`{"password":"`+pwHash+`"}`)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	// 设置完成直接签发 token
	token, _ := s.issueToken()
	writeJSON(w, 200, map[string]any{"token": token, "setup": true})
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request, _ map[string]string) {
	var req struct {
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Password == "" {
		writeErr(w, http.StatusBadRequest, "无效请求")
		return
	}
	var raw []byte
	err := s.db.Pool().QueryRow(s.ctx(), `SELECT value FROM settings WHERE key='admin'`).Scan(&raw)
	if err != nil {
		writeErr(w, http.StatusUnauthorized, "尚未初始化")
		return
	}
	var admin struct{ Password string `json:"password"` }
	_ = json.Unmarshal(raw, &admin)
	if admin.Password != s.hashPassword(req.Password) {
		writeErr(w, http.StatusUnauthorized, "密码错误")
		return
	}
	token, _ := s.issueToken()
	writeJSON(w, 200, map[string]any{"token": token})
}

func (s *Server) issueToken() (string, error) {
	claims := jwt.MapClaims{
		"sub": "admin",
		"exp": time.Now().Add(24 * time.Hour).Unix(),
		"iat": time.Now().Unix(),
	}
	t := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return t.SignedString([]byte(s.cfg.Auth.JWTSecret))
}

func (s *Server) checkAuth(r *http.Request) bool {
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") {
		return false
	}
	tokenStr := strings.TrimPrefix(auth, "Bearer ")
	token, err := jwt.Parse(tokenStr, func(t *jwt.Token) (any, error) {
		return []byte(s.cfg.Auth.JWTSecret), nil
	})
	return err == nil && token.Valid
}

// ---- 健康检查 ----

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request, _ map[string]string) {
	prov := agent.CurrentProvider()
	writeJSON(w, 200, map[string]any{
		"status":        "ok",
		"version":       "0.1.0",
		"llm":           prov.Name(),
		"mock":          prov.Name() == "mock",
		"setup":         s.isSetup(),
		"auth_disabled": s.cfg.Auth.Disabled,
		"time":          time.Now().Format(time.RFC3339),
	})
}

func (s *Server) handleLLMTest(w http.ResponseWriter, r *http.Request, _ map[string]string) {
	prov := agent.CurrentProvider()
	info, err := prov.Ping(r.Context())
	if err != nil {
		writeErr(w, 502, "LLM 不可用: "+err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"llm": prov.Name(), "info": info, "mock": prov.Name() == "mock"})
}

// ---- 工具函数 ----

func (s *Server) ctx() context.Context { return context.Background() }

func matchPath(pattern, path string) (map[string]string, bool) {
	pp := strings.Split(strings.Trim(pattern, "/"), "/")
	rp := strings.Split(strings.Trim(path, "/"), "/")
	if len(pp) != len(rp) {
		return nil, false
	}
	params := map[string]string{}
	for i := range pp {
		if strings.HasPrefix(pp[i], ":") {
			params[pp[i][1:]] = rp[i]
		} else if pp[i] != rp[i] {
			return nil, false
		}
	}
	return params, true
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]any{"error": msg})
}

func parseID(r *http.Request, params map[string]string) (int64, error) {
	idStr := params["id"]
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("无效 id")
	}
	return id, nil
}

// SetStatic 注入内嵌前端（server 侧 route 未命中时兜底）
func (s *Server) SetStatic(h http.Handler) { s.serveStatic = h }