package intercept

import (
	"context"
	"testing"

	"pentigent/db"
)

// 边界用例：IP 范围、url_prefix、webfetch method、子域通配、大小写
func TestGuardEdgeCases(t *testing.T) {
	database, err := db.Open(context.Background(), testDSN())
	if err != nil {
		t.Skipf("需要本地 PostgreSQL: %v", err)
	}
	defer database.Close()
	if err := database.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	// 任务 A：域名范围 example.com + IP 范围 10.0.0.5
	tid, err := database.CreateTask(ctx, "guard-edge", "g", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer database.DeleteTask(ctx, tid)
	_ = database.AddScope(ctx, tid, "example.com", "domain")
	_ = database.AddScope(ctx, tid, "10.0.0.5", "ip")
	_ = database.AddScope(ctx, tid, "https://api.partner.io/v1", "url_prefix")

	g := NewGuard(database)
	if err := g.Bind(ctx, tid); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name string
		tool string
		in   map[string]any
		want string
	}{
		// 域名范围：子域通配
		{"subdomain-in", "webfetch", map[string]any{"url": "https://www.example.com/"}, "allow"},
		{"apex-in", "bash", map[string]any{"command": "nslookup example.com"}, "allow"},
		{"evil-suffix", "webfetch", map[string]any{"url": "https://example.com.evil.net/"}, "deny"},
		// IP 范围：精确
		{"ip-in", "bash", map[string]any{"command": "Test-NetConnection -ComputerName 10.0.0.5 -Port 22"}, "allow"},
		{"ip-out", "bash", map[string]any{"command": "Test-NetConnection -ComputerName 10.0.0.6 -Port 22"}, "deny"},
		// url_prefix
		{"urlprefix-in", "webfetch", map[string]any{"url": "https://api.partner.io/v1/users"}, "allow"},
		{"urlprefix-out", "webfetch", map[string]any{"url": "https://api.partner.io/v2/users"}, "deny"},
		// 大小写
		{"uppercase-in", "webfetch", map[string]any{"url": "https://WWW.EXAMPLE.COM/"}, "allow"},
		// 无目标命令（whoami）应放行
		{"no-target", "bash", map[string]any{"command": "whoami"}, "allow"},
		// POST 方法也要过边界（把 host 抓出来）
		{"post-out", "webfetch", map[string]any{"url": "https://evil.com/login", "method": "POST"}, "deny"},
		{"post-in", "webfetch", map[string]any{"url": "https://example.com/login", "method": "POST"}, "ask"}, // ask 规则命中
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d, err := g.Check(ctx, c.tool, c.in)
			if err != nil {
				t.Fatalf("err: %v", err)
			}
			if d.Action != c.want {
				t.Errorf("%s: got %s (%s), want %s", c.name, d.Action, d.Reason, c.want)
			}
		})
	}
}