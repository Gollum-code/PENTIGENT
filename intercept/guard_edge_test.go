package intercept

import (
	"context"
	"testing"

	"pentigent/db"
)

// 资产黑名单：即使目标被写进任务 scope，也必须被拒（黑名单优先级最高）
func TestAssetBlacklistOverridesScope(t *testing.T) {
	database, err := db.Open(context.Background(), testDSN())
	if err != nil {
		t.Skipf("需要本地 PostgreSQL: %v", err)
	}
	defer database.Close()
	if err := database.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	tid, err := database.CreateTask(ctx, "blacklist", "g", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer database.DeleteTask(ctx, tid)
	// 故意把元数据端点写进 scope —— 黑名单仍应拦
	_ = database.AddScope(ctx, tid, "169.254.169.254", "ip")
	_ = database.AddScope(ctx, tid, "metadata.google.internal", "domain")

	g := NewGuard(database)
	if err := g.Bind(ctx, tid); err != nil {
		t.Fatal(err)
	}
	if len(g.assetRules) == 0 {
		t.Fatal("资产黑名单未加载，Bind 应读取 asset_intercept_rules")
	}
	d, err := g.Check(ctx, "webfetch", map[string]any{"url": "http://169.254.169.254/latest/meta-data/"})
	if err != nil {
		t.Fatal(err)
	}
	if d.Action != "deny" {
		t.Errorf("元数据端点即使在 scope 内也应被黑名单拒绝，得到 %s", d.Action)
	}
	d2, _ := g.Check(ctx, "bash", map[string]any{"command": "curl.exe -s http://169.254.169.254/latest/meta-data/"})
	if d2.Action != "deny" {
		t.Errorf("bash 形式访问元数据端点也应被拒，得到 %s", d2.Action)
	}
	// 正常范围不受影响
	d3, _ := g.Check(ctx, "bash", map[string]any{"command": "nslookup 169.254.169.254.nip.io"})
	if d3.Action == "deny" && d3.Reason == "" {
		t.Errorf("非黑名单目标不应因黑名单被拒")
	}
}

// 模板更新：内置模板不可改，自定义可改
func TestTemplateUpdateGuards(t *testing.T) {
	database, err := db.Open(context.Background(), testDSN())
	if err != nil {
		t.Skipf("需要本地 PostgreSQL: %v", err)
	}
	defer database.Close()
	if err := database.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	list, err := database.ListTaskTemplates(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) == 0 {
		t.Fatal("应有内置模板（schema seed）")
	}
	// 内置模板不可改
	builtin := list[0]
	if err := database.UpdateTaskTemplate(ctx, builtin.ID, db.TaskTemplate{Name: "X", Goal: "Y"}); err == nil {
		t.Error("内置模板更新应报错")
	}
	// 自定义模板可增可改可删
	id, err := database.CreateTaskTemplate(ctx, db.TaskTemplate{Name: "u1", Goal: "g1"})
	if err != nil {
		t.Fatal(err)
	}
	if err := database.UpdateTaskTemplate(ctx, id, db.TaskTemplate{Name: "u2", Goal: "g2"}); err != nil {
		t.Errorf("自定义模板应可更新: %v", err)
	}
	after, _ := database.ListTaskTemplates(ctx)
	found := false
	for _, tp := range after {
		if tp.ID == id && tp.Name == "u2" && tp.Goal == "g2" {
			found = true
		}
	}
	if !found {
		t.Error("模板更新未生效")
	}
	if err := database.DeleteTaskTemplate(ctx, id); err != nil {
		t.Errorf("自定义模板应可删: %v", err)
	}
	// 内置模板不可删
	if err := database.DeleteTaskTemplate(ctx, builtin.ID); err == nil {
		t.Error("内置模板删除应报错")
	}
}

// 回归：并发任务的授权范围隔离。
// 旧实现用全局共享 guard，两个任务 Bind 会互相覆盖 scope，
// 导致 A 能用 B 的范围探测（越权）。现在每任务独立实例，必须互不影响。
func TestPerTaskGuardIsolation(t *testing.T) {
	database, err := db.Open(context.Background(), testDSN())
	if err != nil {
		t.Skipf("需要本地 PostgreSQL: %v", err)
	}
	defer database.Close()
	if err := database.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	tidA, _ := database.CreateTask(ctx, "iso-a", "g", "", nil)
	defer database.DeleteTask(ctx, tidA)
	_ = database.AddScope(ctx, tidA, "example.com", "domain")
	tidB, _ := database.CreateTask(ctx, "iso-b", "g", "", nil)
	defer database.DeleteTask(ctx, tidB)
	_ = database.AddScope(ctx, tidB, "secret-target.org", "domain")

	// 两个独立 guard 实例（修复后的模型）
	guardA := NewGuard(database)
	guardB := NewGuard(database)
	if err := guardA.Bind(ctx, tidA); err != nil {
		t.Fatal(err)
	}
	if err := guardB.Bind(ctx, tidB); err != nil {
		t.Fatal(err)
	}

	// A 只能碰 example.com，不能碰 B 的 secret-target.org
	if d, _ := guardA.Check(ctx, "webfetch", map[string]any{"url": "https://example.com/"}); d.Action != "allow" {
		t.Errorf("A 应能访问自己的 example.com，得到 %s", d.Action)
	}
	if d, _ := guardA.Check(ctx, "webfetch", map[string]any{"url": "https://secret-target.org/"}); d.Action != "deny" {
		t.Errorf("A 必须无法访问 B 的 secret-target.org，得到 %s（越权！）", d.Action)
	}
	// B 相反
	if d, _ := guardB.Check(ctx, "webfetch", map[string]any{"url": "https://secret-target.org/"}); d.Action != "allow" {
		t.Errorf("B 应能访问自己的 secret-target.org，得到 %s", d.Action)
	}
	if d, _ := guardB.Check(ctx, "webfetch", map[string]any{"url": "https://example.com/"}); d.Action != "deny" {
		t.Errorf("B 必须无法访问 A 的 example.com，得到 %s（越权！）", d.Action)
	}
}

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