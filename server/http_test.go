package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"pentigent/config"
	"pentigent/db"
)

func newTestServer(t *testing.T) (*Server, *db.DB) {
	t.Helper()
	d := testDB(t)
	cfg := config.Default()
	cfg.Auth.Disabled = false // 测试认证路径
	return NewServer(cfg, d), d
}

func doReq(t *testing.T, h http.Handler, method, path, token, body string) *httptest.ResponseRecorder {
	t.Helper()
	var r *http.Request
	if body == "" {
		r = httptest.NewRequest(method, path, nil)
	} else {
		r = httptest.NewRequest(method, path, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	return rec
}

func TestHealthEndpoint(t *testing.T) {
	srv, d := newTestServer(t)
	defer d.Close()
	rec := doReq(t, srv.Handler(), "GET", "/api/health", "", "")
	if rec.Code != 200 {
		t.Fatalf("health 状态码=%d, 期望 200", rec.Code)
	}
	var body map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if body["status"] != "ok" && body["status"] != "degraded" {
		t.Errorf("health status=%v (应为 ok/degraded)", body["status"])
	}
	if body["version"] == nil {
		t.Error("health 缺 version")
	}
}

// 未认证访问受保护端点应 401
func TestAuthRequired(t *testing.T) {
	srv, d := newTestServer(t)
	defer d.Close()
	for _, path := range []string{"/api/tasks", "/api/assets", "/api/findings", "/api/stats"} {
		rec := doReq(t, srv.Handler(), "GET", path, "", "")
		if rec.Code != 401 {
			t.Errorf("%s 未认证应 401, got %d", path, rec.Code)
		}
	}
}

func TestLoginAndAccess(t *testing.T) {
	srv, d := newTestServer(t)
	defer d.Close()
	// 恢复成文档默认密码，避免污染后续共享 DB 的测试（e2e 用 admin123）
	defer func() {
		_, _ = d.Pool().Exec(srv.ctx(), `DELETE FROM settings WHERE key='admin'`)
		_, _ = d.Pool().Exec(srv.ctx(), `INSERT INTO settings (key, value) VALUES ('admin', '{"password":"`+
			srv.hashPassword("admin123")+`"}'::jsonb)`)
	}()
	h := srv.Handler()

	// 重置管理员密码，保证测试确定性（DB 是共享的）
	if _, err := d.Pool().Exec(srv.ctx(), `DELETE FROM settings WHERE key='admin'`); err != nil {
		t.Fatal(err)
	}

	// setup
	rec := doReq(t, h, "POST", "/api/auth/setup", "", `{"password":"testpass123"}`)
	if rec.Code != 200 {
		t.Fatalf("setup 失败: %d %s", rec.Code, rec.Body.String())
	}
	var auth struct{ Token string }
	_ = json.Unmarshal(rec.Body.Bytes(), &auth)
	if auth.Token == "" {
		t.Fatal("setup 未返回 token")
	}

	// 错误密码应被拒
	rec = doReq(t, h, "POST", "/api/auth/login", "", `{"password":"wrong"}`)
	if rec.Code != 401 {
		t.Errorf("错误密码应 401, got %d", rec.Code)
	}

	// 带 token 可访问
	rec2 := doReq(t, h, "GET", "/api/tasks", auth.Token, "")
	if rec2.Code != 200 {
		t.Errorf("带 token 访问应 200, got %d", rec2.Code)
	}

	// 无 token 应被拒
	rec3 := doReq(t, h, "GET", "/api/tasks", "", "")
	if rec3.Code != 401 {
		t.Errorf("无 token 应 401, got %d", rec3.Code)
	}
}

// 完整任务生命周期：创建 → 启动 → 暂停 → 克隆 → 删除
func TestTaskLifecycleHTTP(t *testing.T) {
	srv, d := newTestServer(t)
	defer d.Close()
	srv.cfg.Auth.Disabled = true // 简化测试
	h := srv.Handler()

	// 创建
	rec := doReq(t, h, "POST", "/api/tasks", "",
		`{"name":"http-test","goal":"Probe example.com","scope":["example.com"]}`)
	if rec.Code != 200 {
		t.Fatalf("创建任务失败: %d %s", rec.Code, rec.Body.String())
	}
	var task struct{ ID int64 }
	_ = json.Unmarshal(rec.Body.Bytes(), &task)
	if task.ID == 0 {
		t.Fatal("未返回任务 id")
	}

	// 空 goal 应拒绝
	rec = doReq(t, h, "POST", "/api/tasks", "", `{"goal":""}`)
	if rec.Code != 400 {
		t.Errorf("空 goal 应 400, got %d", rec.Code)
	}

	// 备注
	rec = doReq(t, h, "POST", "/api/tasks/"+itoa(task.ID)+"/notes", "", `{"notes":"已确认授权"}`)
	if rec.Code != 200 {
		t.Errorf("设置备注失败: %d", rec.Code)
	}

	// 克隆
	rec = doReq(t, h, "POST", "/api/tasks/"+itoa(task.ID)+"/clone", "", `{}`)
	if rec.Code != 200 {
		t.Errorf("克隆失败: %d %s", rec.Code, rec.Body.String())
	}

	// 暂停/停止（任务未在跑也应该成功）
	doReq(t, h, "POST", "/api/tasks/"+itoa(task.ID)+"/stop", "", "")
	doReq(t, h, "POST", "/api/tasks/"+itoa(task.ID)+"/pause", "", "")

	// 删除
	rec = doReq(t, h, "DELETE", "/api/tasks/"+itoa(task.ID), "", "")
	if rec.Code != 200 {
		t.Errorf("删除失败: %d", rec.Code)
	}

	// 删除后详情应 404
	rec = doReq(t, h, "GET", "/api/tasks/"+itoa(task.ID), "", "")
	if rec.Code != 404 {
		t.Errorf("已删除任务详情应 404, got %d", rec.Code)
	}
}

// 重置数据需要 confirm=RESET
func TestResetDataRequiresConfirm(t *testing.T) {
	srv, d := newTestServer(t)
	defer d.Close()
	srv.cfg.Auth.Disabled = true
	h := srv.Handler()

	// 缺少 confirm 应 400
	rec := doReq(t, h, "POST", "/api/reset", "", `{"confirm":"no"}`)
	if rec.Code != 400 {
		t.Errorf("缺少 confirm 应 400, got %d", rec.Code)
	}
	// 错误 confirm 应 400
	rec = doReq(t, h, "POST", "/api/reset", "", `{"confirm":"wrong"}`)
	if rec.Code != 400 {
		t.Errorf("错误 confirm 应 400, got %d", rec.Code)
	}
}

// 漏洞状态接口校验
func TestFindingStatusValidation(t *testing.T) {
	srv, d := newTestServer(t)
	defer d.Close()
	srv.cfg.Auth.Disabled = true
	h := srv.Handler()

	// 非法 status 应 400
	rec := doReq(t, h, "POST", "/api/findings/1/status", "", `{"status":"bogus"}`)
	if rec.Code != 400 {
		t.Errorf("非法 status 应 400, got %d", rec.Code)
	}
}

// 分页参数边界
func TestPaginationParams(t *testing.T) {
	srv, d := newTestServer(t)
	defer d.Close()
	srv.cfg.Auth.Disabled = true
	h := srv.Handler()

	// 非法 offset 应被钳制到默认值，不 500
	rec := doReq(t, h, "GET", "/api/tasks?limit=abc&offset=-5", "", "")
	if rec.Code != 200 {
		t.Errorf("非法分页参数应被容错为默认, got %d", rec.Code)
	}
	// 超大 limit 应被钳制
	rec = doReq(t, h, "GET", "/api/tasks?limit=99999", "", "")
	if rec.Code != 200 {
		t.Errorf("超大 limit 应被钳制, got %d", rec.Code)
	}
}

// LLM 测试端点（mock 应可用）
func TestLLMTestEndpoint(t *testing.T) {
	srv, d := newTestServer(t)
	defer d.Close()
	srv.cfg.Auth.Disabled = true
	rec := doReq(t, srv.Handler(), "POST", "/api/llm/test", "", "")
	if rec.Code != 200 && rec.Code != 502 {
		t.Errorf("llm/test 应返回 200 或 502, got %d", rec.Code)
	}
}

// CSV 公式注入：LLM 分析的标题可能来自攻击者可控内容，导出时必须中和
func TestCSVFormulaInjection(t *testing.T) {
	cases := []struct{ in, want string }{
		{"=HYPERLINK(\"http://evil\",\"click\")", `"'=HYPERLINK(""http://evil"",""click"")"`},
		{"@SUM(1+1)", "'@SUM(1+1)"},
		{"+cmd|'/c calc'!A0", "'+cmd|'/c calc'!A0"},
		{"normal title", "normal title"},
		{"a,b", `"a,b"`},
	}
	for _, c := range cases {
		if got := csvEscape(c.in); got != c.want {
			t.Errorf("csvEscape(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func itoa(v int64) string { return strconv.FormatInt(v, 10) }