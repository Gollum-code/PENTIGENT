package db

import (
	"context"
	"fmt"
	"testing"
	"time"
)

func testDB(t *testing.T) *DB {
	t.Helper()
	d, err := Open(context.Background(), "postgres://postgres:postgres@127.0.0.1:5432/artex?sslmode=disable")
	if err != nil {
		t.Skipf("需要本地 PostgreSQL: %v", err)
	}
	if err := d.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	return d
}

func TestSchemaIdempotent(t *testing.T) {
	d := testDB(t)
	defer d.Close()
	ctx := context.Background()
	// 连跑三次应无错（幂等）
	for i := 0; i < 3; i++ {
		if err := d.Migrate(ctx); err != nil {
			t.Fatalf("migrate run %d: %v", i+1, err)
		}
	}
}

func TestTaskLifecycle(t *testing.T) {
	d := testDB(t)
	defer d.Close()
	ctx := context.Background()

	cid, err := d.EnsureCompany(ctx, "test-co-"+t.Name())
	if err != nil {
		t.Fatal(err)
	}
	tid, err := d.CreateTask(ctx, "t", "goal", "desc", &cid)
	if err != nil {
		t.Fatal(err)
	}
	defer d.DeleteTask(ctx, tid)

	if err := d.SetTaskStatus(ctx, tid, "running", ""); err != nil {
		t.Fatal(err)
	}
	task, err := d.GetTask(ctx, tid)
	if err != nil {
		t.Fatal(err)
	}
	if task.Status != "running" {
		t.Errorf("status=%s want running", task.Status)
	}
	// GetTask 现在带 token 聚合，必须能正常扫
	if task.TokensIn != 0 || task.TokensOut != 0 {
		t.Errorf("empty task should have 0 tokens, got %d/%d", task.TokensIn, task.TokensOut)
	}
	if task.StartedAt == "" {
		t.Errorf("started_at should be set after running")
	}
}

func TestListTasksScansFinishedAt(t *testing.T) {
	d := testDB(t)
	defer d.Close()
	ctx := context.Background()

	cid, _ := d.EnsureCompany(ctx, "test-co-list-"+t.Name())
	tid, _ := d.CreateTask(ctx, "list-task", "g", "d", &cid)
	defer d.DeleteTask(ctx, tid)
	_ = d.SetTaskStatus(ctx, tid, "done", "")

	tasks, total, err := d.ListTasks(ctx, "", "", 100, 0)
	if err != nil {
		t.Fatal(err)
	}
	if total < 1 {
		t.Errorf("total=%d want >=1", total)
	}
	found := false
	for _, tsk := range tasks {
		if tsk.ID == tid {
			found = true
			if tsk.Status != "done" {
				t.Errorf("status=%s", tsk.Status)
			}
		}
	}
	if !found {
		t.Errorf("created task not returned by ListTasks")
	}
}

func TestExplorationAndNodes(t *testing.T) {
	d := testDB(t)
	defer d.Close()
	ctx := context.Background()

	cid, _ := d.EnsureCompany(ctx, "test-co-exp-"+t.Name())
	tid, _ := d.CreateTask(ctx, "exp", "goal here", "", &cid)
	defer d.DeleteTask(ctx, tid)

	eid, err := d.CreateExploration(ctx, tid, "goal here")
	if err != nil {
		t.Fatal(err)
	}
	// goal 节点
	gid, _ := d.CreateGoal(ctx, eid, "G1", "desc")
	// intent
	iid, _ := d.AddIntent(ctx, eid, "I1", "desc")
	// claim
	claimed, err := d.ClaimNextIntent(ctx, eid, "w1")
	if err != nil {
		t.Fatal(err)
	}
	if claimed == nil || claimed.ID != iid {
		t.Fatalf("expected to claim intent %d, got %+v", iid, claimed)
	}
	if claimed.Status != "running" {
		t.Errorf("claimed status=%s", claimed.Status)
	}
	// 再 claim 应为空（唯一 open）
	c2, _ := d.ClaimNextIntent(ctx, eid, "w2")
	if c2 != nil {
		t.Errorf("second claim should be nil, got %+v", c2)
	}

	// prove goal
	if err := d.ProveGoals(ctx, eid, nil); err != nil {
		t.Fatal(err)
	}
	g, _ := d.GetNode(ctx, gid)
	if g.Status != "met" {
		t.Errorf("goal status=%s want met", g.Status)
	}
}

func TestReclaimStuckIntents(t *testing.T) {
	d := testDB(t)
	defer d.Close()
	ctx := context.Background()

	cid, _ := d.EnsureCompany(ctx, "test-co-reclaim-"+t.Name())
	tid, _ := d.CreateTask(ctx, "reclaim", "g", "", &cid)
	defer d.DeleteTask(ctx, tid)
	eid, _ := d.CreateExploration(ctx, tid, "g")

	iid, _ := d.AddIntent(ctx, eid, "I", "d")
	// claim → running
	c, _ := d.ClaimNextIntent(ctx, eid, "w")
	if c == nil {
		t.Fatal("failed to claim")
	}
	// 模拟超时：把 claimed_at 推到很久以前
	_, _ = d.Pool().Exec(ctx, `UPDATE exploration_nodes SET claimed_at = now() - interval '10 minutes' WHERE id=$1`, iid)
	// 回收（超时 1 分钟）
	n, err := d.ReclaimStuckIntents(ctx, eid, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("reclaimed %d want 1", n)
	}
	node, _ := d.GetNode(ctx, iid)
	if node.Status != "open" {
		t.Errorf("after reclaim status=%s want open", node.Status)
	}
	// 可重新 claim
	c2, _ := d.ClaimNextIntent(ctx, eid, "w2")
	if c2 == nil {
		t.Errorf("should be re-claimable")
	}
}

func TestAssetDedupAndAnchors(t *testing.T) {
	d := testDB(t)
	defer d.Close()
	ctx := context.Background()

	cid, _ := d.EnsureCompany(ctx, "test-co-asset-"+t.Name())
	host := fmt.Sprintf("dedup-%d.example", time.Now().UnixNano())
	// 同一 root_domain 插两次应幂等
	id1, ins1, err := d.InsertAsset(ctx, cid, Asset{Type: "root_domain", Domain: host})
	if err != nil {
		t.Fatal(err)
	}
	id2, ins2, err := d.InsertAsset(ctx, cid, Asset{Type: "root_domain", Domain: host})
	if err != nil {
		t.Fatal(err)
	}
	if !ins1 {
		t.Errorf("first insert should be new")
	}
	if ins2 {
		t.Errorf("second insert should be deduped")
	}
	if id1 != id2 {
		t.Errorf("dedup should return same id: %d vs %d", id1, id2)
	}

	// service 去重
	s1, _, _ := d.InsertAsset(ctx, cid, Asset{Type: "service", URL: "https://" + host})
	s2, insS, _ := d.InsertAsset(ctx, cid, Asset{Type: "service", URL: "https://" + host})
	if s1 != s2 || insS {
		t.Errorf("service dedup failed: %d/%d ins=%v", s1, s2, insS)
	}

	// endpoint 去重（含 method）
	e1, _, _ := d.InsertAsset(ctx, cid, Asset{Type: "endpoint", URL: "https://" + host + "/admin", Method: "GET"})
	e2, insE, _ := d.InsertAsset(ctx, cid, Asset{Type: "endpoint", URL: "https://" + host + "/admin", Method: "GET"})
	if e1 != e2 || insE {
		t.Errorf("endpoint dedup failed")
	}
}

func TestFindingsDedup(t *testing.T) {
	d := testDB(t)
	defer d.Close()
	ctx := context.Background()

	cid, _ := d.EnsureCompany(ctx, "test-co-find-"+t.Name())
	tid, _ := d.CreateTask(ctx, "find", "g", "", &cid)
	defer d.DeleteTask(ctx, tid)

	f1, ins1, err := d.ReportFinding(ctx, Finding{TaskID: &tid, Title: "SQLi", Severity: "high", Evidence: map[string]any{"x": 1}})
	if err != nil {
		t.Fatal(err)
	}
	f2, ins2, err := d.ReportFinding(ctx, Finding{TaskID: &tid, Title: "SQLi", Severity: "high", Evidence: map[string]any{"x": 2}})
	if err != nil {
		t.Fatal(err)
	}
	if !ins1 || ins2 || f1 != f2 {
		t.Errorf("finding dedup failed: %d/%d ins=%v/%v", f1, f2, ins1, ins2)
	}
	// 列表过滤
	fs, total, err := d.ListFindings(ctx, &tid, "high", "", 100, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 1 || total != 1 {
		t.Errorf("ListFindings severity filter returned %d rows (total=%d) want 1", len(fs), total)
	}
	// 分页
	fs2, _, err := d.ListFindings(ctx, &tid, "high", "", 1, 0)
	if err != nil || len(fs2) != 1 {
		t.Errorf("paged findings %d rows err=%v want 1", len(fs2), err)
	}
}

func TestLogActivityNilMaps(t *testing.T) {
	d := testDB(t)
	defer d.Close()
	ctx := context.Background()
	// nil Input/Output 必须兜底成 {}（列是 NOT NULL）
	_, err := d.LogActivity(ctx, Activity{Role: "engine", Step: "x"})
	if err != nil {
		t.Fatalf("LogActivity with nil maps should succeed: %v", err)
	}
}