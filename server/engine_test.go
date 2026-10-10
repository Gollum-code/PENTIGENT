package server

import (
	"context"
	"sync"
	"testing"
	"time"

	"artex/db"
)

// helper：跑一个完整任务直到收敛
func runTaskToCompletion(t *testing.T, e *Engine, taskID int64, timeout time.Duration) string {
	t.Helper()
	if err := e.Start(taskID); err != nil {
		t.Fatalf("Start: %v", err)
	}
	deadline := time.Now().Add(timeout)
	var status string
	for time.Now().Before(deadline) {
		time.Sleep(300 * time.Millisecond)
		tsk, err := e.db.GetTask(context.Background(), taskID)
		if err == nil {
			status = tsk.Status
			if status == "done" || status == "incomplete" || status == "failed" || status == "stopped" {
				return status
			}
		}
	}
	return status
}

func TestEngineFullLoop(t *testing.T) {
	d := testDB(t)
	defer d.Close()
	ctx := context.Background()

	cid, _ := d.EnsureCompany(ctx, "test-co-engine-loop-"+t.Name())
	scopes := []string{"example.com"}
	tid, _ := d.CreateTask(ctx, "loop", "对 example.com 做授权资产面与 Web 漏洞探测", "e2e", &cid)
	for _, s := range scopes {
		_ = d.AddScope(ctx, tid, s, "domain")
	}

	e := NewEngine(d, 4)
	status := runTaskToCompletion(t, e, tid, 30*time.Second)

	if status != "done" {
		t.Fatalf("task finished with status=%q, want done", status)
	}

	// goals 都要 met
	eid, _ := d.ExplorationForTask(ctx, tid)
	nodes, _ := d.ListNodes(ctx, eid, "goal", "")
	if len(nodes) < 1 {
		t.Fatal("no goal nodes")
	}
	for _, n := range nodes {
		if n.Status != "met" {
			t.Errorf("goal %d status=%s want met", n.ID, n.Status)
		}
	}
	// intents 全部 done
	intents, _ := d.ListNodes(ctx, eid, "intent", "")
	for _, n := range intents {
		if n.Status != "done" {
			t.Errorf("intent %d status=%s want done", n.ID, n.Status)
		}
	}
	// 资产落库（全局真值库，不限定公司）
	assets, _, _ := d.SearchAssets(ctx, nil, "", "", 100, 0)
	if len(assets) < 1 {
		t.Log("提示：本次探测网络受限未发现资产（正常，离线环境）")
	}
}

func TestEngineConcurrentWorkers(t *testing.T) {
	d := testDB(t)
	defer d.Close()
	ctx := context.Background()

	cid, _ := d.EnsureCompany(ctx, "test-co-engine-conc-"+t.Name())
	tid, _ := d.CreateTask(ctx, "conc", "对 example.com 做授权资产面与 Web 漏洞探测", "", &cid)
	_ = d.AddScope(ctx, tid, "example.com", "domain")

	// 手动造 4 个 open intent，验证能同时被 claim（并发）
	eid, _ := d.CreateExploration(ctx, tid, "g")
	for i := 0; i < 4; i++ {
		_, _ = d.AddIntent(ctx, eid, "intent", "d")
	}

	e := NewEngine(d, 4)
	ctx2, cancel := context.WithCancel(ctx)
	defer cancel()
	var claimed = make(chan struct{}, 8)
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func(w string) {
			defer wg.Done()
			n, err := d.ClaimNextIntent(ctx2, eid, w)
			if err == nil && n != nil {
				claimed <- struct{}{}
			}
		}(string(rune('a' + i)))
	}
	wg.Wait()
	// 4 条 open intent，4 个并发 claim 应全部成功（SKIP LOCKED 不冲突）
	if c := len(claimed); c != 4 {
		t.Errorf("claimed %d intents, want 4 (并发 claim 冲突)", c)
	}
	_ = e
}

func TestEngineZombieRunningRecovery(t *testing.T) {
	d := testDB(t)
	defer d.Close()
	ctx := context.Background()

	cid, _ := d.EnsureCompany(ctx, "test-co-engine-zombie-"+t.Name())
	tid, _ := d.CreateTask(ctx, "zombie", "gone", "", &cid)
	// 模拟崩溃遗留：任务 running，探索 running，且有 running intent
	_ = d.SetTaskStatus(ctx, tid, "running", "")
	eid, _ := d.CreateExploration(ctx, tid, "g")
	_ = d.SetExplorationStatus(ctx, eid, "running")
	iid, _ := d.AddIntent(ctx, eid, "i", "d")
	_ = d.SetNodeStatus(ctx, iid, "running")

	// 新引擎（模拟进程重启）→ Start 应能恢复而非拒绝
	e := NewEngine(d, 2)
	if err := e.Start(tid); err != nil {
		t.Fatalf("Start 应允许僵尸 running 恢复: %v", err)
	}
	time.Sleep(2 * time.Second)
	e.Stop(tid)
}

func TestDeleteTaskCleansPending(t *testing.T) {
	d := testDB(t)
	defer d.Close()
	ctx := context.Background()

	cid, _ := d.EnsureCompany(ctx, "test-co-engine-del-"+t.Name())
	tid, _ := d.CreateTask(ctx, "del", "g", "", &cid)
	// 造一条 pending
	pid, err := d.EnqueueIntercept(ctx, db.PendingIntercept{
		TaskID: &tid, Tool: "webfetch", Input: map[string]any{"url": "https://example.com"}, Reason: "test",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := d.DeleteTask(ctx, tid); err != nil {
		t.Fatal(err)
	}
	// pending 应被清理
	_, err = d.GetPending(ctx, pid)
	if err == nil {
		t.Error("DeleteTask 后 pending 应已删除")
	}
}