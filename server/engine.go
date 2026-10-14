package server

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"pentigent/agent"
	"pentigent/db"
	"pentigent/intercept"
)

// Engine 事件驱动闭环：图变更 → debounce → planner → frontier → N workers → 写回 → 再唤醒
type Engine struct {
	db     *db.DB
	store  *db.DB
	guard  *intercept.Guard
	workers int
	debounce int // planner 唤醒 debounce（ms）
	idleTimeout time.Duration // 无变更信号时的兜底收敛检查
	intentBudget int // 单任务最大意图数（0=不限），防真实 LLM 无限扩展烧钱
	tokenBudget  int // 单任务最大 token 消耗（0=不限）

	mu      sync.Mutex
	running map[int64]context.CancelFunc

	workerMu sync.Mutex
	wcount   map[int64]int
}

// intentTimeout worker 单条意图执行超时；超时未完成的 running intent 会被回收为 open
const intentTimeout = 5 * time.Minute

func NewEngine(database *db.DB, workers int) *Engine {
	if workers <= 0 {
		workers = 4
	}
	return &Engine{
		db:          database,
		store:       database,
		guard:       intercept.NewGuard(database),
		workers:     workers,
		debounce:    500,
		idleTimeout: 30 * time.Second,
		intentBudget: 15,   // 默认 15 条意图（真实 LLM 会持续扩展，需硬上限）
		tokenBudget:  150000, // 默认 15 万 token
		running:     map[int64]context.CancelFunc{},
		wcount:      map[int64]int{},
	}
}

// Start 启动任务：初始化探索 + goals 分解 + 进入闭环
func (e *Engine) Start(taskID int64) error {
	e.mu.Lock()
	if _, ok := e.running[taskID]; ok {
		e.mu.Unlock()
		return fmt.Errorf("任务已在运行")
	}
	ctx, cancel := context.WithCancel(context.Background())
	e.running[taskID] = cancel
	e.mu.Unlock()

	go func() {
		defer func() {
			e.mu.Lock()
			delete(e.running, taskID)
			e.mu.Unlock()
			cancel()
		}()
		e.run(ctx, taskID)
	}()

	return nil
}

// Stop 停止任务
func (e *Engine) Stop(taskID int64) {
	e.mu.Lock()
	cancel, ok := e.running[taskID]
	e.mu.Unlock()
	if ok {
		cancel()
	}
}

// WaitAllIdle 等待所有运行中的任务自然收敛（优雅关闭用）。
// 给定 timeout，超时后返回仍有运行中的任务数。
func (e *Engine) WaitAllIdle(timeout time.Duration) int {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		e.mu.Lock()
		n := len(e.running)
		e.mu.Unlock()
		if n == 0 {
			return 0
		}
		time.Sleep(200 * time.Millisecond)
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	return len(e.running)
}

// RunningCount 当前运行中的任务数
func (e *Engine) RunningCount() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return len(e.running)
}

// StopAll 停止所有运行中的任务
func (e *Engine) StopAll() {
	e.mu.Lock()
	defer e.mu.Unlock()
	for id, cancel := range e.running {
		cancel()
		delete(e.running, id)
	}
}

func (e *Engine) IsRunning(taskID int64) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	_, ok := e.running[taskID]
	return ok
}

// findResumable 找可断点续跑的探索：任务最近一个 paused/stopped 的探索，且仍有未完成 intent。
// 同时兜底：status=running 但引擎不再运行（进程崩溃留下的僵尸）也视为可恢复。
// 返回 (explorationID, 是否恢复, err)
func (e *Engine) findResumable(ctx context.Context, taskID int64) (int64, bool, error) {
	explorationID, err := e.store.ExplorationForTask(ctx, taskID)
	if err != nil {
		return 0, false, nil // 无历史探索
	}
	expl, err := e.store.GetExploration(ctx, explorationID)
	if err != nil {
		return 0, false, nil
	}
	switch expl.Status {
	case "paused", "stopped":
		// 正常暂停 → 只恢复还有未完成 intent 的
		hasOpen, err := e.store.HasOpenIntent(ctx, explorationID)
		if err == nil && hasOpen {
			return explorationID, true, nil
		}
	case "running":
		// 僵尸 running：引擎未在跑该任务说明上次进程被杀，重置未完成 intent 后恢复
		if !e.IsRunning(taskID) {
			return explorationID, true, nil
		}
	}
	return 0, false, nil
}

// runGoals 首次运行时做目标分解 + 约束登记 + 建 goal 节点
func (e *Engine) runGoals(ctx context.Context, taskID int64, task *db.Task, explorationID int64) {
	gr := agentGoalsRun(ctx, task)
	// 记录授权范围落库失败（否则任务无 scope → guard 拦一切 → 空跑）
	for _, s := range gr.Scope {
		if err := e.db.AddScope(ctx, taskID, s.Pattern, s.Kind); err != nil {
			log.Printf("engine: task %d AddScope(%s) 失败: %v", taskID, s.Pattern, err)
		}
	}
	for _, c := range gr.Constraints {
		if err := e.db.AddConstraint(ctx, taskID, c.Kind, c.Pattern); err != nil {
			log.Printf("engine: task %d AddConstraint(%s) 失败: %v", taskID, c.Pattern, err)
		}
	}
	if len(gr.Goals) == 0 {
		gr.Goals = fallbackGoals(task.Goal, task.Description)
	}
	for _, g := range gr.Goals {
		if _, err := e.store.CreateGoal(ctx, explorationID, g.Title, g.Description); err != nil {
			log.Printf("engine: task %d CreateGoal(%s) 失败: %v", taskID, g.Title, err)
		}
	}
	tid := int64(taskID)
	_ = e.recordEngineActivity(tid, explorationID, "goals", "目标分解", gr.InputTokens, gr.OutputTokens, gr.Error)
}

// run 一次任务的完整生命周期
func (e *Engine) run(ctx context.Context, taskID int64) {
	log.Printf("engine: task %d start", taskID)
	if err := e.db.SetTaskStatus(ctx, taskID, "running", ""); err != nil {
		log.Printf("engine: set running: %v", err)
	}

	// 绑定 guard 任务上下文（加载 scope / 约束）
	if err := e.guard.Bind(ctx, taskID); err != nil {
		log.Printf("engine: guard bind: %v", err)
	}

	task, err := e.db.GetTask(ctx, taskID)
	if err != nil {
		_ = e.db.SetTaskStatus(ctx, taskID, "failed", err.Error())
		return
	}

	// 创建探索，或从暂停处恢复（断点续跑）
	explorationID, resuming, err := e.findResumable(ctx, taskID)
	if err != nil {
		_ = e.db.SetTaskStatus(ctx, taskID, "failed", err.Error())
		return
	}
	if resuming {
		log.Printf("engine: task %d 从探索 %d 断点续跑", taskID, explorationID)
		_ = e.store.SetExplorationStatus(ctx, explorationID, "running")
		// 暂停时执行中的 worker 已终止，其 running intent 重新入队
		if n, err := e.store.ResetRunningIntents(ctx, explorationID); err == nil && n > 0 {
			log.Printf("engine: 断点续跑，重置 %d 条 running intent", n)
		}
		taskIDCopy := int64(taskID)
		_ = e.recordEngineActivity(taskIDCopy, explorationID, "resume", "断点续跑", 0, 0, "")
	} else {
		explorationID, err = e.store.CreateExploration(ctx, taskID, task.Goal)
		if err != nil {
			_ = e.db.SetTaskStatus(ctx, taskID, "failed", err.Error())
			return
		}
	}

	// ---- Goals 分解（main agent）——仅首次运行需要 ----
	if !resuming {
		e.runGoals(ctx, taskID, task, explorationID)
	}

	// 若描述里有明确域名，确保 task_scope 已登记（幂等，恢复时也补一遍）
	if err := e.scopeFromTaskDesc(ctx, taskID, task.Description); err != nil {
		log.Printf("engine: scope from desc: %v", err)
	}
	// 绑定 guard scope + 资产黑名单。Bind 失败绝不能忽略：
	// guard 会带着未加载的黑名单/规则运行 = 安全降级（fail-open）。
	if err := e.guard.Bind(ctx, taskID); err != nil {
		log.Printf("engine: task %d guard Bind 失败，终止以避免安全降级: %v", taskID, err)
		_ = e.store.SetExplorationStatus(ctx, explorationID, "failed")
		_ = e.db.SetTaskStatus(ctx, taskID, "failed", "guard 初始化失败: "+err.Error())
		return
	}

	// ---- 闭环：事件驱动，planner ↔ workers ----
	// worker 每次写回图变更 → 发 wake 信号 → debounce 后唤醒 planner。
	// 不再"等所有 worker 跑完再唤醒 planner"——worker 干活途中新发现也能及时触发规划调整。
	wake := make(chan struct{}, 64)
	signal := func() {
		select {
		case wake <- struct{}{}:
		default:
		}
	}

	// 回收卡死的 intent（worker 崩溃/进程被杀留下的 running）
	if reclaimed, err := e.store.ReclaimStuckIntents(ctx, explorationID, intentTimeout); err != nil {
		log.Printf("engine: reclaim: %v", err)
	} else if reclaimed > 0 {
		log.Printf("engine: 回收 %d 条卡死 intent", reclaimed)
	}

	// 首次派发：把当前 open intent 交给并发 worker
	e.dispatchAsync(ctx, taskID, explorationID, signal)

	// 唤醒 planner（无状态：只读图+todolist）
	planRes := e.planOnce(ctx, taskID, explorationID)
	plannerErrCount := 0
	if planRes.GoalProved {
		_ = e.db.SetExplorationStatus(ctx, explorationID, "done")
		_ = e.db.SetTaskStatus(ctx, taskID, "done", "")
		log.Printf("engine: task %d 目标达成", taskID)
		return
	}

	// 等待图变更，直到收敛
	idle := time.NewTimer(e.idleTimeout)
	defer idle.Stop()
	for {
		select {
		case <-ctx.Done():
			_ = e.db.SetExplorationStatus(ctx, explorationID, "stopped")
			_ = e.db.SetTaskStatus(ctx, taskID, "stopped", "")
			log.Printf("engine: task %d stopped", taskID)
			return

		case <-wake:
			// debounce：合并短时间内的连续变更，避免高频唤醒
			time.Sleep(time.Duration(e.debounce) * time.Millisecond)
			for {
				select {
				case <-wake:
				default:
					goto drained
				}
			}
		drained:
			// 回收卡死 intent
			if reclaimed, err := e.store.ReclaimStuckIntents(ctx, explorationID, intentTimeout); err != nil {
				log.Printf("engine: reclaim: %v", err)
			} else if reclaimed > 0 {
				log.Printf("engine: 回收 %d 条卡死 intent", reclaimed)
			}
			// 有 open intent 就继续派发
			e.dispatchAsync(ctx, taskID, explorationID, signal)
			// 唤醒 planner
			planRes = e.planOnce(ctx, taskID, explorationID)
			if planRes.GoalProved {
				_ = e.db.SetExplorationStatus(ctx, explorationID, "done")
				_ = e.db.SetTaskStatus(ctx, taskID, "done", "")
				log.Printf("engine: task %d 目标达成", taskID)
				return
			}

		case <-idle.C:
			// 兜底：worker 异常终止未发信号。只做派发与收敛，不调 LLM
			// （planner 仅在图变更信号到达时唤醒，避免空转烧 token）
			e.dispatchAsync(ctx, taskID, explorationID, signal)
		}
		idle.Reset(e.idleTimeout)
		hasFrontier, _ := e.store.HasOpenIntent(ctx, explorationID)
		// LLM 调用失败不算"无新方向"：退避后重试，避免上游抖动导致任务误判收敛。
		// 用递增退避（不是紧密 signal 重试），否则上游持续故障时会打爆 API 造成自我 DoS。
		if planRes.Error != "" {
			if plannerErrCount < 3 {
				plannerErrCount++
				backoff := time.Duration(plannerErrCount*plannerErrCount) * 3 * time.Second
				log.Printf("engine: task %d planner LLM 失败(第%d次), %v 后重试: %s", taskID, plannerErrCount, backoff, planRes.Error)
				select {
				case <-ctx.Done():
					return
				case <-time.After(backoff):
				}
				continue // 直接重跑本轮（重新 planOnce）
			}
			// 连续多次失败 → 标记失败并停止，避免无限重试烧钱
			_ = e.db.SetExplorationStatus(ctx, explorationID, "failed")
			_ = e.db.SetTaskStatus(ctx, taskID, "failed", "planner LLM 连续失败: "+planRes.Error)
			log.Printf("engine: task %d planner 连续 LLM 失败，终止", taskID)
			return
		}
		if len(planRes.NewIntents) == 0 && !hasFrontier && e.activeWorkers(taskID) == 0 {
			allMet, metCount, totalGoals := e.goalsAllMet(ctx, explorationID)
			if allMet {
				_ = e.db.SetExplorationStatus(ctx, explorationID, "done")
				_ = e.db.SetTaskStatus(ctx, taskID, "done", "")
				log.Printf("engine: task %d 收敛，全部 goal 达成 (%d/%d)", taskID, metCount, totalGoals)
			} else {
				_ = e.db.SetExplorationStatus(ctx, explorationID, "incomplete")
				msg := fmt.Sprintf("planner 无新方向但目标未全部达成 (met %d/%d)", metCount, totalGoals)
				_ = e.db.SetTaskStatus(ctx, taskID, "incomplete", msg)
				log.Printf("engine: task %d %s", taskID, msg)
			}
			return
		}

		// 预算护栏：意图数或 token 超上限 → 停止（防真实 LLM 无限扩展烧钱）
		if e.intentBudget > 0 {
			nIntents, _ := e.store.CountNodes(ctx, explorationID, "intent", "")
			if nIntents >= e.intentBudget {
				msg := fmt.Sprintf("达到意图预算上限 %d，停止规划", e.intentBudget)
				_ = e.db.SetExplorationStatus(ctx, explorationID, "incomplete")
				_ = e.db.SetTaskStatus(ctx, taskID, "incomplete", msg)
				log.Printf("engine: task %d %s", taskID, msg)
				return
			}
		}
		if e.tokenBudget > 0 {
			spent, _ := e.store.SumTokens(ctx, taskID)
			if spent >= e.tokenBudget {
				msg := fmt.Sprintf("达到 token 预算上限 %d，停止", e.tokenBudget)
				_ = e.db.SetExplorationStatus(ctx, explorationID, "incomplete")
				_ = e.db.SetTaskStatus(ctx, taskID, "incomplete", msg)
				log.Printf("engine: task %d %s（已用 %d）", taskID, msg, spent)
				return
			}
		}
	}
}

// planOnce 唤醒一次 planner 并处理产出（todolist 写回 / prove_goal）
func (e *Engine) planOnce(ctx context.Context, taskID, explorationID int64) agent.PlanResult {
	plannerState := e.buildPlannerState(ctx, taskID, explorationID)
	planRes := plannerRun(ctx, e.db, explorationID, plannerState)
	_ = e.recordEngineActivity(taskID, explorationID, "planner", "唤醒规划", planRes.InputTokens, planRes.OutputTokens, planRes.Error)

	// 跨唤醒共享记忆：把本次新派的动作写回 todolist
	if len(planRes.NewIntentText) > 0 {
		agent.NewPlanner().UpdateTodolist(ctx, NewStoreBridge(storeImpl{db: e.db}), explorationID, planRes.NewIntentText)
	}
	return planRes
}

// dispatchAsync 并发 worker：每个 claim 一条 open intent 执行，不阻塞等待。
// 每个 worker 完成时触发 signal（图变更 → 唤醒 planner）。
func (e *Engine) dispatchAsync(ctx context.Context, taskID, explorationID int64, signal func()) {
	for i := 0; i < e.workers; i++ {
		if !e.acquireWorker(taskID) {
			break // 已达并发上限
		}
		go func() {
			defer e.releaseWorker(taskID)
			defer signal()
			intent, err := e.store.ClaimNextIntent(ctx, explorationID, fmt.Sprintf("engine-%d-%d", taskID, time.Now().UnixNano()))
			if err != nil {
				log.Printf("engine: claim: %v", err)
				return
			}
			if intent == nil {
				return // frontier 空，无活可干
			}
			e.executeIntent(ctx, taskID, explorationID, intent)
		}()
	}
}

// ---- worker 并发计数 ----

// workerCounts 每个任务的运行中 worker 数
type workerCounts struct {
	mu sync.Mutex
	n  map[int64]int
}

func (e *Engine) acquireWorker(taskID int64) bool {
	e.workerMu.Lock()
	defer e.workerMu.Unlock()
	if e.wcount[taskID] >= e.workers {
		return false
	}
	e.wcount[taskID]++
	return true
}

func (e *Engine) releaseWorker(taskID int64) {
	e.workerMu.Lock()
	if e.wcount[taskID] > 0 {
		e.wcount[taskID]--
	}
	e.workerMu.Unlock()
}

func (e *Engine) activeWorkers(taskID int64) int {
	e.workerMu.Lock()
	defer e.workerMu.Unlock()
	return e.wcount[taskID]
}

// executeIntent 单个 worker 执行一条意图
func (e *Engine) executeIntent(ctx context.Context, taskID, explorationID int64, intent *db.Node) {
	log.Printf("engine: worker 执行意图 %d: %s", intent.ID, intent.Title)
	res := agentWorkerRun(ctx, e, taskID, explorationID, intent)

	status := "done"
	if res.Status == "blocked" {
		status = "blocked"
	}
	if res.Status == "error" {
		status = "blocked"
	}
	_ = e.store.SetNodeStatus(ctx, intent.ID, status)

	// 意图完成后，若有 findings，把 fact/finding 挂回 goal 链路（简化：不展开）
	log.Printf("engine: 意图 %d 完成 status=%s facts=%d findings=%d assets=%d",
		intent.ID, status, res.NewFacts, res.NewFindings, res.NewAssets)
}

// goalsAllMet 检查该探索下所有 goal 是否都已 met。
// 返回 (allMet, metCount, totalGoals)
func (e *Engine) goalsAllMet(ctx context.Context, explorationID int64) (bool, int, int) {
	goals, err := e.store.ListNodes(ctx, explorationID, "goal", "")
	if err != nil {
		return false, 0, 0
	}
	if len(goals) == 0 {
		// 没有 goal 节点：无法判定达成，按未完成处理避免误报成功
		return false, 0, 0
	}
	met := 0
	for _, g := range goals {
		if g.Status == "met" {
			met++
		}
	}
	return met == len(goals), met, len(goals)
}

// buildPlannerState 构造 planner 态势快照
func (e *Engine) buildPlannerState(ctx context.Context, taskID, explorationID int64) map[string]any {
	task, err := e.db.GetTask(ctx, taskID)
	if err != nil {
		task = &db.Task{Goal: ""}
	}
	nodes, _ := e.store.ListNodes(ctx, explorationID, "", "")

	open := 0
	done := 0
	facts := 0
	findings := 0
	met := false
	for _, n := range nodes {
		switch n.Type {
		case "intent":
			if n.Status == "open" || n.Status == "running" {
				open++
			} else {
				done++
			}
		case "fact":
			facts++
		case "finding":
			findings++
		case "goal":
			if n.Status == "met" {
				met = true
			}
		}
	}
	return map[string]any{
		"goal":         task.Goal,
		"target":       e.firstScope(ctx, taskID),
		"open_intents": open,
		"done_intents": done,
		"facts":        facts,
		"findings":     findings,
		"goals_met":    met,
	}
}

func (e *Engine) firstScope(ctx context.Context, taskID int64) string {
	scope, err := e.db.ListScope(ctx, taskID)
	if err != nil || len(scope) == 0 {
		return ""
	}
	return scope[0].Pattern
}

// recordEngineActivity 记录引擎/planner 层 activity
func (e *Engine) recordEngineActivity(taskID, explorationID int64, step, summary string, tokIn, tokOut int, errMsg string) error {
	status := "ok"
	if errMsg != "" {
		status = "error"
	}
	_, err := e.store.LogActivity(context.Background(), db.Activity{
		TaskID:        &taskID,
		ExplorationID: &explorationID,
		Role:          "planner",
		Step:          step,
		Input:         map[string]any{"summary": summary},
		Output:        map[string]any{"error": errMsg},
		Status:        status,
		InputTokens:   tokIn,
		OutputTokens:  tokOut,
	})
	return err
}

func (e *Engine) scopeFromTaskDesc(ctx context.Context, taskID int64, desc string) error {
	for _, host := range extractDomains(desc) {
		if err := e.db.AddScope(ctx, taskID, host, "domain"); err != nil {
			return err
		}
	}
	return nil
}