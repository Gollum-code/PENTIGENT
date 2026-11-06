package server

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"pentigent/config"
	"pentigent/db"
)

func TestPasswordHashAndVerify(t *testing.T) {
	srv := &Server{cfg: &config.Config{}}
	h, err := passwordHash("secret123")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(h, "$2") {
		t.Fatalf("期望 bcrypt 哈希，got %q", h)
	}
	if ok, _ := srv.verifyPassword(h, "secret123"); !ok {
		t.Error("正确密码校验失败")
	}
	if ok, _ := srv.verifyPassword(h, "wrong"); ok {
		t.Error("错误密码不应通过")
	}
}

func TestVerifyLegacySHA256Upgrades(t *testing.T) {
	cfg := &config.Config{}
	cfg.Auth.JWTSecret = "test-secret"
	srv := &Server{cfg: cfg}

	sum := sha256.Sum256([]byte("secret123" + cfg.Auth.JWTSecret))
	legacy := hex.EncodeToString(sum[:])

	ok, upgraded := srv.verifyPassword(legacy, "secret123")
	if !ok {
		t.Fatal("旧 SHA-256 哈希应能登录")
	}
	if upgraded == "" || !strings.HasPrefix(upgraded, "$2") {
		t.Fatalf("登录成功应返回 bcrypt 升级哈希，got %q", upgraded)
	}
	if ok2, _ := srv.verifyPassword(upgraded, "secret123"); !ok2 {
		t.Error("升级后的哈希应能校验通过")
	}
}

// 任务描述里的文件名/技术名词不应被当成授权域名
func TestExtractDomainsFiltersNonHosts(t *testing.T) {
	got := extractDomains("对 example.com 做测试，涉及 node.js、report.md、config.json")
	want := map[string]bool{"example.com": true}
	if len(got) != 1 {
		t.Fatalf("期望只提取 example.com，got %v", got)
	}
	for _, d := range got {
		if !want[d] {
			t.Errorf("不应提取 %q", d)
		}
	}
}

// 规则校验：坏正则/非法枚举必须在写入前被拦下。
// 否则一条 deny 规则会"看着生效但永远不命中"，属于最危险的静默失效。
func TestValidateInterceptRule(t *testing.T) {
	ok := db.InterceptRule{
		Name: "r", MatchTarget: "tool_input", MatchType: "regex",
		Pattern: `(?i)rm\s+-[rf]`, Action: "deny", Priority: 100,
	}
	if err := validateInterceptRule(ok); err != nil {
		t.Fatalf("合法规则不应报错: %v", err)
	}
	stringRule := db.InterceptRule{MatchTarget: "tool_input", MatchType: "string", Pattern: "rm -rf", Action: "deny"}
	if err := validateInterceptRule(stringRule); err != nil {
		t.Errorf("string 模式的字面量无需按正则校验: %v", err)
	}
	badRe := db.InterceptRule{MatchTarget: "tool_input", MatchType: "regex", Pattern: `rm -[rf(`, Action: "deny"}
	if err := validateInterceptRule(badRe); err == nil {
		t.Error("坏正则应被拒绝")
	}
	for _, r := range []db.InterceptRule{
		{MatchTarget: "bogus"},
		{MatchTarget: "tool_input", MatchType: "bogus"},
		{MatchTarget: "tool_input", MatchType: "string", Action: "bogus"},
	} {
		if err := validateInterceptRule(r); err == nil {
			t.Errorf("非法字段应被拒绝: %+v", r)
		}
	}
}

// 描述里直接写 IP 时也要推断进授权范围
func TestExtractDomainsIncludesIP(t *testing.T) {
	got := extractDomains("目标 10.0.0.5 和 api.example.com，注意 999.1.1.1 不是 IP")
	set := map[string]bool{}
	for _, d := range got {
		set[d] = true
	}
	if !set["10.0.0.5"] || !set["api.example.com"] {
		t.Errorf("缺少期望目标: %v", got)
	}
	if set["999.1.1.1"] {
		t.Errorf("非法 IP 不应被提取: %v", got)
	}
}

// 描述里的 IPv6 也要能推断进授权范围（否则 IPv6 目标全程被硬边界拦截）
func TestExtractDomainsIncludesIPv6(t *testing.T) {
	got := extractDomains("目标 ::1 与 2001:db8::1，时间 12:34:56 不是地址")
	set := map[string]bool{}
	for _, d := range got {
		set[d] = true
	}
	if !set["::1"] || !set["2001:db8::1"] {
		t.Errorf("缺少 IPv6 目标: %v", got)
	}
	if set["12:34:56"] {
		t.Errorf("时间戳不应被当成 IPv6: %v", got)
	}
}

// 未匹配的 /api/* 必须返回 JSON 404，而不是被 SPA 兜底成 HTML 200。
func TestUnknownAPIReturnsJSON404(t *testing.T) {
	cfg := config.Default()
	cfg.Auth.Disabled = true
	srv := &Server{cfg: cfg}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/definitely-not-a-route", nil)
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("未知 API 应返回 404，got %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "application/json") {
		t.Errorf("未知 API 应返回 JSON，Content-Type=%q", ct)
	}
}

// CORS 不能回显任意第三方 Origin（API 支持同源 cookie 鉴权，通配符会被滥用）。
func TestCORSDoesNotReflectForeignOrigin(t *testing.T) {
	cfg := config.Default()
	cfg.Auth.Disabled = true
	srv := &Server{cfg: cfg}

	foreign := httptest.NewRequest("OPTIONS", "/api/tasks", nil)
	foreign.Host = "pentigent.local"
	foreign.Header.Set("Origin", "https://evil.example")
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, foreign)
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Errorf("第三方 Origin 不应获得 ACAO，got %q", got)
	}

	same := httptest.NewRequest("OPTIONS", "/api/tasks", nil)
	same.Host = "pentigent.local"
	same.Header.Set("Origin", "http://pentigent.local")
	rec2 := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec2, same)
	if got := rec2.Header().Get("Access-Control-Allow-Origin"); got != "http://pentigent.local" {
		t.Errorf("同源 Origin 应被回显，got %q", got)
	}

	// 显式白名单（开发期前端跑在别的端口）
	srv.cfg.Server.AllowedOrigins = []string{"http://localhost:3000"}
	dev := httptest.NewRequest("OPTIONS", "/api/tasks", nil)
	dev.Host = "127.0.0.1:8080"
	dev.Header.Set("Origin", "http://localhost:3000")
	rec3 := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec3, dev)
	if got := rec3.Header().Get("Access-Control-Allow-Origin"); got != "http://localhost:3000" {
		t.Errorf("白名单 Origin 应被回显，got %q", got)
	}
}
