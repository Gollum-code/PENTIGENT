package server

import (
	"context"
	"testing"

	"artex/config"
	"artex/db"
)

func testDB(t *testing.T) *db.DB {
	t.Helper()
	d, err := db.Open(context.Background(), "postgres://postgres:postgres@127.0.0.1:5432/artex?sslmode=disable")
	if err != nil {
		t.Skipf("需要本地 PostgreSQL: %v", err)
	}
	if err := d.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	return d
}

func TestMatchPath(t *testing.T) {
	cases := []struct {
		pattern, path string
		ok            bool
		id            string
	}{
		{"/api/tasks", "/api/tasks", true, ""},
		{"/api/tasks/:id", "/api/tasks/5", true, "5"},
		{"/api/tasks/:id/start", "/api/tasks/5/start", true, "5"},
		{"/api/tasks/:id", "/api/tasks/5/start", false, ""},
		{"/api/auth/login", "/api/auth/login", true, ""},
		{"/api/tasks", "/api/assets", false, ""},
	}
	for _, c := range cases {
		params, ok := matchPath(c.pattern, c.path)
		if ok != c.ok {
			t.Errorf("pattern=%s path=%s got ok=%v want %v", c.pattern, c.path, ok, c.ok)
			continue
		}
		if c.ok && params["id"] != c.id {
			t.Errorf("pattern=%s path=%s id got %q want %q", c.pattern, c.path, params["id"], c.id)
		}
	}
}

func TestGoalsAllMet(t *testing.T) {
	d := testDB(t)
	defer d.Close()
	ctx := context.Background()

	cid, _ := d.EnsureCompany(ctx, "test-co-engine-"+t.Name())
	tid, _ := d.CreateTask(ctx, "engine", "goal", "", &cid)
	defer d.DeleteTask(ctx, tid)

	e := NewEngine(d, 2)

	// 空探索：没有 goal → not met（防误报成功）
	allMet, met, total := e.goalsAllMet(ctx, 999999)
	if allMet || total != 0 {
		t.Errorf("non-existent exploration should be not-met, got allMet=%v total=%d", allMet, total)
	}

	// 建两个 goal，一个 met 一个没
	eid, _ := d.CreateExploration(ctx, tid, "g")
	g1, _ := d.CreateGoal(ctx, eid, "G1", "")
	_, _ = d.CreateGoal(ctx, eid, "G2", "")
	allMet, met, total = e.goalsAllMet(ctx, eid)
	if allMet || met != 0 || total != 2 {
		t.Errorf("before met: allMet=%v met=%d total=%d want false/0/2", allMet, met, total)
	}
	// met 其中一个
	_ = d.SetNodeStatus(ctx, g1, "met")
	allMet, met, total = e.goalsAllMet(ctx, eid)
	if allMet || met != 1 || total != 2 {
		t.Errorf("partial: allMet=%v met=%d total=%d want false/1/2", allMet, met, total)
	}
	// 全部 met
	nodes, _ := d.ListNodes(ctx, eid, "goal", "")
	for _, n := range nodes {
		_ = d.SetNodeStatus(ctx, n.ID, "met")
	}
	allMet, met, total = e.goalsAllMet(ctx, eid)
	if !allMet || met != 2 || total != 2 {
		t.Errorf("all met: allMet=%v met=%d total=%d want true/2/2", allMet, met, total)
	}
}

func TestServerSetupAndHealth(t *testing.T) {
	d := testDB(t)
	defer d.Close()
	cfg := config.Default()
	srv := NewServer(cfg, d)
	if srv == nil {
		t.Fatal("NewServer returned nil")
	}
	if srv.Engine() == nil {
		t.Fatal("Engine should not be nil")
	}
}

func TestStoreBridgeSatisfiesAgentStore(t *testing.T) {
	// 编译期断言：StoreBridge 必须实现 agent.Store
	d := testDB(t)
	defer d.Close()
	b := NewStoreBridge(storeImpl{db: d})
	if b == nil {
		t.Fatal("StoreBridge nil")
	}
	_ = b
}