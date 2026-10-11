package intercept

import (
	"context"
	"os"
	"testing"

	"pentigent/db"
)

// 用临时 PostgreSQL 测试 guard 集成行为。
// DSN 可用 PENTIGENT_TEST_DSN 覆盖（CI 里指向 service 容器）。
func testDSN() string {
	if v := os.Getenv("PENTIGENT_TEST_DSN"); v != "" {
		return v
	}
	return "postgres://postgres:postgres@127.0.0.1:5432/pentigent?sslmode=disable"
}

func TestGuardIntegration(t *testing.T) {
	database, err := db.Open(context.Background(), testDSN())
	if err != nil {
		t.Skipf("需要本地 PostgreSQL: %v", err)
	}
	defer database.Close()
	// 建表（幂等）。CI 里是全新库，不迁移会 "relation tasks does not exist"
	if err := database.Migrate(context.Background()); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	tid, err := database.CreateTask(context.Background(), "guard-test", "test", "test", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer database.DeleteTask(context.Background(), tid)
	_ = database.AddScope(context.Background(), tid, "example.com", "domain")

	g := NewGuard(database)
	if err := g.Bind(context.Background(), tid); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name string
		tool string
		in   map[string]any
		want string
	}{
		{"scope-in-webfetch", "webfetch", map[string]any{"url": "https://example.com/login"}, "allow"},
		{"scope-out-webfetch", "webfetch", map[string]any{"url": "https://evil.org/"}, "deny"},
		{"cloud-metadata", "webfetch", map[string]any{"url": "http://169.254.169.254/"}, "deny"},
		{"rm-rf", "bash", map[string]any{"command": "rm -rf /tmp/x"}, "deny"},
		{"shadow", "bash", map[string]any{"command": "cat /etc/shadow"}, "deny"},
		{"scope-in-bash", "bash", map[string]any{"command": "nslookup example.com"}, "allow"},
		{"scope-out-bash", "bash", map[string]any{"command": "nslookup notinscope.org"}, "deny"},
		{"nslookup-flags", "bash", map[string]any{"command": "nslookup -type=A example.com 2>&1"}, "allow"},
		{"curl-url-host", "bash", map[string]any{"command": `curl.exe -s -o NUL http://example.com/`}, "allow"},
		{"graph-tool", "insert_assets", map[string]any{"assets": []any{}}, "allow"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d, err := g.Check(context.Background(), c.tool, c.in)
			if err != nil {
				t.Fatalf("err: %v", err)
			}
			if d.Action != c.want {
				t.Errorf("got %s (%s), want %s", d.Action, d.Reason, c.want)
			}
		})
	}
}

func TestExtractHosts(t *testing.T) {
	cases := []struct {
		cmd  string
		want []string
	}{
		{"nslookup example.com", []string{"example.com"}},
		{"nslookup -type=A www.example.com 2>&1", []string{"www.example.com"}},
		{"curl -s -m 5 -o NUL -w '%{http_code}' https://api.example.com/x", []string{"api.example.com"}},
		{"nslookup notinscope.org", []string{"notinscope.org"}},
		{"whoami", nil},
		{"echo hello", nil},
		{"ping -n 1 8.8.8.8", nil},
	}
	for _, c := range cases {
		got := extractHosts("bash", map[string]any{"command": c.cmd})
		if len(got) != len(c.want) {
			t.Errorf("cmd=%q got %v, want %v", c.cmd, got, c.want)
			continue
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Errorf("cmd=%q got[%d]=%q want %q", c.cmd, i, got[i], c.want[i])
			}
		}
	}
}