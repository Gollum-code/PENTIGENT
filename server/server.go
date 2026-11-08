package server

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"pentigent/agent"
	"pentigent/config"
	"pentigent/db"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

// Version 构建版本（可通过 -ldflags "-X pentigent/server.Version=x.y.z" 注入）
var Version = "0.1.0"

// maxBodyBytes 请求体大小上限（防超大 body 打内存/DoS）
const maxBodyBytes = 1 << 20 // 1 MiB

// setupLockID 收敛并发首次设置（advisory xact lock）
const setupLockID int64 = 7271_0002

// route 列表在启动时构建一次：
// Handler 对每个请求都要遍历它，若每次现构建会重复分配 ~40 条路由的切片。
type Server struct {
	cfg    *config.Config
	db     *db.DB
	engine *Engine
	// serveStatic 由 cmd 注入（go:embed 前端）
	serveStatic http.Handler

	routesList []route

	// LLM 健康缓存（避免 health 被 LLM 延迟阻塞）
	llmMu          sync.Mutex
	lastLLMCheck   time.Time
	lastLLMOK      bool
	lastLLMLatency float64
	lastLLMInfo    string

	// 登录 / 免鉴权 LLM 探测限流
	loginLimiter *rateLimiter
	llmLimiter   *rateLimiter

	// SSE 单轮询广播
	sse *sseHub
}

// refreshLLM 后台探测 LLM 连通性并更新缓存
func (s *Server) refreshLLM(prov agent.Provider) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	start := time.Now()
	info, err := prov.Ping(ctx)
	latency := float64(time.Since(start).Microseconds()) / 1000
	s.llmMu.Lock()
	defer s.llmMu.Unlock()
	s.lastLLMCheck = time.Now()
	s.lastLLMLatency = latency
	if err != nil {
		s.lastLLMOK = false
		s.lastLLMInfo = err.Error()
	} else {
		s.lastLLMOK = true
		s.lastLLMInfo = info
	}
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
	// 引擎参数从配置注入（0 = 保持默认/不限，见 Engine 字段语义）
	if cfg.Agent.Debounce > 0 {
		engine.debounce = cfg.Agent.Debounce
	}
	if cfg.Agent.IntentBudget >= 0 {
		engine.intentBudget = cfg.Agent.IntentBudget
	}
	if cfg.Agent.TokenBudget >= 0 {
		engine.tokenBudget = cfg.Agent.TokenBudget
	}
	if cfg.Agent.MaxRounds > 0 {
		engine.maxRounds = cfg.Agent.MaxRounds
	}
	// 0 = 不限；配置来自 config.Default()/JSON，缺省为 30 分钟
	engine.maxRuntime = time.Duration(cfg.Agent.MaxRuntimeSec) * time.Second
	s := &Server{
		cfg:          cfg,
		db:           database,
		engine:       engine,
		loginLimiter: newRateLimiter(10, time.Minute),
		llmLimiter:   newRateLimiter(10, time.Minute),
		sse:          newSSEHub(database),
	}
	s.routesList = s.routes() // 单 goroutine 内构建一次，请求处理不再重复分配
	return s
}

// routesFor 返回路由表：优先用启动时缓存的一份，
// 直接构造 Server{} 的测试没有缓存则现场构建兜底。
func (s *Server) routesFor() []route {
	if s.routesList == nil {
		s.routesList = s.routes()
	}
	return s.routesList
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
		{Method: "GET", Pattern: "/api/tasks/:id/history", Handler: s.handleTaskHistory, Auth: true},
		{Method: "GET", Pattern: "/api/export/assets.csv", Handler: s.handleExportAssetsCSV, Auth: true},
		{Method: "GET", Pattern: "/api/export/findings.csv", Handler: s.handleExportFindingsCSV, Auth: true},
		{Method: "GET", Pattern: "/api/search", Handler: s.handleGlobalSearch, Auth: true},

		// 漏洞详情
		{Method: "GET", Pattern: "/api/findings/:id", Handler: s.handleGetFinding, Auth: true},

		// 审批
		{Method: "GET", Pattern: "/api/intercept/pending", Handler: s.handlePendingList, Auth: true},
		{Method: "GET", Pattern: "/api/intercept/rules", Handler: s.handleRulesList, Auth: true},
		{Method: "POST", Pattern: "/api/intercept/rules", Handler: s.handleCreateRule, Auth: true},
		{Method: "DELETE", Pattern: "/api/intercept/rules/:id", Handler: s.handleDeleteRule, Auth: true},
		{Method: "POST", Pattern: "/api/intercept/:id/decision", Handler: s.handleInterceptDecision, Auth: true},

		// 模板 / 报告设置
		{Method: "GET", Pattern: "/api/templates", Handler: s.handleListTemplates, Auth: true},
		{Method: "POST", Pattern: "/api/templates", Handler: s.handleCreateTemplate, Auth: true},
		{Method: "PUT", Pattern: "/api/templates/:id", Handler: s.handleUpdateTemplate, Auth: true},
		{Method: "DELETE", Pattern: "/api/templates/:id", Handler: s.handleDeleteTemplate, Auth: true},
		{Method: "GET", Pattern: "/api/report-settings", Handler: s.handleGetReportSettings, Auth: true},
		{Method: "POST", Pattern: "/api/report-settings", Handler: s.handleUpdateReportSettings, Auth: true},

		// API 文档
		{Method: "GET", Pattern: "/api/openapi.yaml", Handler: s.handleOpenAPI, Auth: false},
	}
}

func (s *Server) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 请求日志（只记 path，不记 query，避免 token/敏感参数进日志）
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w}
		w = rec
		defer func() {
			log.Printf("http: %s %s %d %dB %s",
				r.Method, r.URL.Path, rec.status, rec.bytes, time.Since(start).Round(time.Millisecond))
		}()

		// 基础安全头（前端是静态内嵌单二进制，同源；CSP 收紧到 self）
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "same-origin")
		w.Header().Set("Content-Security-Policy",
			"default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; connect-src 'self'")

		// 请求体大小上限（JSON 解码器无法自行限制）
		if r.Body != nil {
			r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
		}

		// CORS：前端由 go:embed 同源提供，正常不需要跨域。
		// 通配符 "*" 配合支持 cookie 的鉴权接口会被第三方站点的脚本滥用（带凭据请求），
		// 因此只在"同源（origin host == 本服务 host）"或"显式配置进白名单"时回显 origin。
		w.Header().Add("Vary", "Origin")
		if origin := r.Header.Get("Origin"); origin != "" {
			if u, err := url.Parse(origin); err == nil && (strings.EqualFold(u.Host, r.Host) || s.originAllowed(origin)) {
				w.Header().Set("Access-Control-Allow-Origin", origin)
				w.Header().Set("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE,OPTIONS")
				w.Header().Set("Access-Control-Allow-Headers", "Content-Type,Authorization")
			}
		}
		if r.Method == "OPTIONS" {
			w.WriteHeader(200)
			return
		}

		// CSRF：cookie 鉴权的状态变更请求必须同源（Authorization 客户端不受影响）
		if !sameOriginOK(r) {
			writeErr(w, http.StatusForbidden, "跨站请求被拒绝")
			return
		}

		for _, rt := range s.routesFor() {
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
		// API 路径没命中任何路由：返回 JSON 404，不能兜底到 SPA 的 index.html
		//（否则前端收到 HTML 当作数据解析、报错信息也难排查）。
		if strings.HasPrefix(r.URL.Path, "/api/") {
			writeErr(w, http.StatusNotFound, "接口不存在: "+r.Method+" "+r.URL.Path)
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

// passwordHash 用 bcrypt 生成口令哈希（自带随机盐，慢哈希，抗暴力破解）。
func passwordHash(password string) (string, error) {
	h, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(h), err
}

// verifyPassword 校验口令，并兼容升级前的 SHA-256 哈希。
// 返回 (ok, upgradedHash)：ok 且 upgradedHash 非空时，调用方应把新 bcrypt 哈希写回。
func (s *Server) verifyPassword(stored, password string) (bool, string) {
	if strings.HasPrefix(stored, "$2") {
		return bcrypt.CompareHashAndPassword([]byte(stored), []byte(password)) == nil, ""
	}
	// 旧版：sha256(password + jwtSecret)，登录成功后立刻升级为 bcrypt
	h := sha256.Sum256([]byte(password + s.cfg.Auth.JWTSecret))
	expect := hex.EncodeToString(h[:])
	if subtle.ConstantTimeCompare([]byte(expect), []byte(stored)) != 1 {
		return false, ""
	}
	if upgraded, err := passwordHash(password); err == nil {
		return true, upgraded
	}
	return true, ""
}

// setAuthCookie 登录成功后写 HttpOnly cookie：同源 EventSource/下载链接会自动携带。
// 同时仍返回 token，兼容命令行/API 客户端用 Authorization 头。
func (s *Server) setAuthCookie(w http.ResponseWriter, token string, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     "pentigent_token",
		Value:    token,
		Path:     "/",
		MaxAge:   int((24 * time.Hour).Seconds()),
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteStrictMode,
	})
}

func (s *Server) isSetup(ctx context.Context) bool {
	var v []byte
	err := s.db.Pool().QueryRow(ctx, `SELECT value FROM settings WHERE key='admin'`).Scan(&v)
	return err == nil && len(v) > 0
}

func (s *Server) handleSetup(w http.ResponseWriter, r *http.Request, _ map[string]string) {
	if ok, retry := s.loginLimiter.allow(clientIP(r)); !ok {
		w.Header().Set("Retry-After", strconv.Itoa(int(retry.Seconds())+1))
		writeErr(w, http.StatusTooManyRequests, "尝试过于频繁，请稍后再试")
		return
	}
	if s.isSetup(r.Context()) {
		writeErr(w, http.StatusBadRequest, "已完成初始设置")
		return
	}
	var req struct {
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || len(req.Password) < 6 {
		writeErr(w, http.StatusBadRequest, "密码至少 6 位")
		return
	}
	pwHash, err := passwordHash(req.Password)
	if err != nil {
		writeErr(w, 500, "生成密码哈希失败")
		return
	}
	// 事务 + advisory lock：并发 setup 只会有一个成功，避免后到者覆盖先到者密码。
	tx, err := s.db.Pool().Begin(r.Context())
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	defer tx.Rollback(r.Context())
	if _, err := tx.Exec(r.Context(), `SELECT pg_advisory_xact_lock($1)`, setupLockID); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	// 事务内重查：锁后再次确认，避免并发 setup 覆盖
	var v []byte
	if err := tx.QueryRow(r.Context(), `SELECT value FROM settings WHERE key='admin'`).Scan(&v); err == nil && len(v) > 0 {
		writeErr(w, http.StatusBadRequest, "已完成初始设置")
		return
	}
	if _, err := tx.Exec(r.Context(),
		`INSERT INTO settings (key, value) VALUES ('admin', $1::jsonb)
		 ON CONFLICT (key) DO UPDATE SET value=EXCLUDED.value`,
		`{"password":`+strconv.Quote(pwHash)+`}`); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	token, err := s.issueToken()
	if err != nil {
		writeErr(w, 500, "签发 token 失败")
		return
	}
	s.setAuthCookie(w, token, isSecureRequest(r))
	writeJSON(w, 200, map[string]any{"token": token, "setup": true})
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request, _ map[string]string) {
	if ok, retry := s.loginLimiter.allow(clientIP(r)); !ok {
		w.Header().Set("Retry-After", strconv.Itoa(int(retry.Seconds())+1))
		writeErr(w, http.StatusTooManyRequests, "尝试过于频繁，请稍后再试")
		return
	}
	var req struct {
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Password == "" {
		writeErr(w, http.StatusBadRequest, "无效请求")
		return
	}
	var raw []byte
	err := s.db.Pool().QueryRow(r.Context(), `SELECT value FROM settings WHERE key='admin'`).Scan(&raw)
	if err != nil {
		writeErr(w, http.StatusUnauthorized, "尚未初始化")
		return
	}
	var admin struct {
		Password string `json:"password"`
	}
	_ = json.Unmarshal(raw, &admin)
	ok, upgraded := s.verifyPassword(admin.Password, req.Password)
	if !ok {
		writeErr(w, http.StatusUnauthorized, "密码错误")
		return
	}
	// 旧 SHA-256 哈希登录成功后自动升级
	if upgraded != "" {
		_, _ = s.db.Pool().Exec(r.Context(),
			`UPDATE settings SET value=$1::jsonb WHERE key='admin'`,
			`{"password":`+strconv.Quote(upgraded)+`}`)
	}
	token, err := s.issueToken()
	if err != nil {
		writeErr(w, 500, "签发 token 失败")
		return
	}
	s.setAuthCookie(w, token, isSecureRequest(r))
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

// checkAuth 依次尝试：Authorization 头 → cookie → SSE 的 ?token=。
// SSE（EventSource）无法设置请求头，因此仅对 /events 路径允许查询参数兜底。
func (s *Server) checkAuth(r *http.Request) bool {
	var tokenStr string
	if auth := r.Header.Get("Authorization"); strings.HasPrefix(auth, "Bearer ") {
		tokenStr = strings.TrimPrefix(auth, "Bearer ")
	}
	if tokenStr == "" {
		if c, err := r.Cookie("pentigent_token"); err == nil {
			tokenStr = c.Value
		}
	}
	if tokenStr == "" && strings.HasSuffix(r.URL.Path, "/events") {
		tokenStr = r.URL.Query().Get("token")
	}
	if tokenStr == "" {
		return false
	}
	// 显式限定签名算法，避免 alg 混淆类攻击
	token, err := jwt.Parse(tokenStr, func(t *jwt.Token) (any, error) {
		if t.Method != jwt.SigningMethodHS256 {
			return nil, fmt.Errorf("unexpected signing method: %s", t.Method.Alg())
		}
		return []byte(s.cfg.Auth.JWTSecret), nil
	})
	return err == nil && token.Valid
}

// ---- 健康检查 ----

// handleHealth 健康检查 + 可观测性：DB 连通性、LLM 延迟、运行任务数、待审批积压
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request, _ map[string]string) {
	prov := agent.CurrentProvider()

	// DB 连通性与延迟
	dbOK := true
	var dbMs float64
	start := time.Now()
	if err := s.db.Pool().Ping(r.Context()); err != nil {
		dbOK = false
	}
	dbMs = float64(time.Since(start).Microseconds()) / 1000

	// LLM 连通性：用短超时，且后台异步刷新缓存（health 不被 LLM 拖慢）
	s.llmMu.Lock()
	stale := s.lastLLMCheck.IsZero() || time.Since(s.lastLLMCheck) > 30*time.Second
	llmOK := s.lastLLMOK
	llmMs := s.lastLLMLatency
	llmErr := s.lastLLMInfo
	s.llmMu.Unlock()
	if stale {
		go s.refreshLLM(prov)
	}

	// 运行中任务数 / 待审批积压（直接 COUNT，避免拉全表只为计数）
	running := s.engine.RunningCount()
	pendingCount := 0
	if err := s.db.Pool().QueryRow(r.Context(),
		`SELECT COUNT(*) FROM intercept_pending WHERE status='pending'`).Scan(&pendingCount); err != nil {
		log.Printf("health: count pending: %v", err)
	}

	status := "ok"
	if !dbOK || !llmOK {
		status = "degraded"
	}

	writeJSON(w, 200, map[string]any{
		"status":        status,
		"version":       Version,
		"llm":           prov.Name(),
		"mock":          prov.Name() == "mock",
		"setup":         s.isSetup(r.Context()),
		"auth_disabled": s.cfg.Auth.Disabled,
		"time":          time.Now().Format(time.RFC3339),
		"db":            map[string]any{"ok": dbOK, "latency_ms": dbMs},
		"llm_status":    map[string]any{"ok": llmOK, "latency_ms": llmMs, "error": llmErr},
		"engine":        map[string]any{"running_tasks": running, "pending_intercepts": pendingCount},
	})
}

func (s *Server) handleLLMTest(w http.ResponseWriter, r *http.Request, _ map[string]string) {
	// 免鉴权端点，限制调用频率，避免被用来消耗上游 token / 探测端点
	if ok, retry := s.llmLimiter.allow(clientIP(r)); !ok {
		w.Header().Set("Retry-After", strconv.Itoa(int(retry.Seconds())+1))
		writeErr(w, http.StatusTooManyRequests, "LLM 探测过于频繁，请稍后再试")
		return
	}
	prov := agent.CurrentProvider()
	info, err := prov.Ping(r.Context())
	if err != nil {
		writeErr(w, 502, "LLM 不可用: "+err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"llm": prov.Name(), "info": info, "mock": prov.Name() == "mock"})
}

// originAllowed 判断 origin 是否在显式跨域白名单内（server.allowed_origins / PENTIGENT_ALLOWED_ORIGINS）。
func (s *Server) originAllowed(origin string) bool {
	if s.cfg == nil {
		return false
	}
	origin = strings.TrimRight(strings.TrimSpace(origin), "/")
	for _, o := range s.cfg.Server.AllowedOrigins {
		if strings.EqualFold(strings.TrimRight(strings.TrimSpace(o), "/"), origin) {
			return true
		}
	}
	return false
}

// ---- 工具函数 ----

func (s *Server) ctx() context.Context { return context.Background() }

func matchPath(pattern, path string) (map[string]string, bool) {
	// 快路径：绝大多数路由（约 40 条里的 35 条）不含路径参数，
	// 直接字符串比较即可，避免为每条路由做两次 Split 分配。
	if !strings.Contains(pattern, ":") {
		if pattern == path {
			return map[string]string{}, true
		}
		return nil, false
	}
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
