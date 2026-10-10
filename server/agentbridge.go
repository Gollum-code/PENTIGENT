package server

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"artex/agent"
	"artex/db"
	"artex/intercept"
)

// agentGoalsRun 调用 goals agent 做目标分解 + 约束提取
func agentGoalsRun(ctx context.Context, task *db.Task) agent.GoalsResult {
	return agent.GoalsRun(ctx, task.Goal, task.Description, "", []string{})
}

// fallbackGoals 兜底：LLM 未返回 goals 时按任务目标构造
func fallbackGoals(goal, desc string) []agent.Goal {
	host := firstDomain(goal + " " + desc)
	if host == "" {
		host = "example.com"
	}
	return []agent.Goal{
		{Title: fmt.Sprintf("探测 %s 的资产面", host), Description: fmt.Sprintf("枚举 %s 的子域名、端口与 Web 服务", host)},
		{Title: fmt.Sprintf("发现 %s 的常见漏洞", host), Description: "对发现的资产做漏洞检查并报告"},
	}
}

// plannerRun 唤醒 planner
func plannerRun(ctx context.Context, database *db.DB, explorationID int64, state map[string]any) agent.PlanResult {
	pl := agent.NewPlanner()
	st := agent.PlannerState{}
	if goal, ok := state["goal"].(string); ok {
		st.Goal = goal
	}
	if target, ok := state["target"].(string); ok {
		st.Target = target
	}
	if v, ok := state["open_intents"].(int); ok {
		st.OpenIntents = v
	}
	if v, ok := state["done_intents"].(int); ok {
		st.DoneIntents = v
	}
	if v, ok := state["facts"].(int); ok {
		st.Facts = v
	}
	if v, ok := state["findings"].(int); ok {
		st.Findings = v
	}
	if v, ok := state["goals_met"].(bool); ok {
		st.GoalsMet = v
	}
	return pl.Run(ctx, NewStoreBridge(storeImpl{db: database}), explorationID, st)
}

// agentWorkerRun 运行一个 worker 直到意图完成
func agentWorkerRun(ctx context.Context, e *Engine, taskID, explorationID int64, intent *db.Node) agent.WorkerResult {
	// 资产归属公司：查任务真实绑定的 company_id（不再硬编码）
	var companyID int64
	if task, err := e.db.GetTask(ctx, taskID); err == nil && task.CompanyID != nil {
		companyID = *task.CompanyID
	}
	w := &agent.Worker{
		Store:     NewStoreBridge(storeImpl{db: e.db}),
		Guard:     &guardAdapter{g: e.guard},
		CompanyID: companyID,
	}
	return w.Run(ctx, taskID, explorationID, intent, 12)
}

// ---- store 桥 ----

// storeImpl 把 *db.DB 暴露为 agent.Store
type storeImpl struct{ db *db.DB }

// StoreBridge 实现 agent.Store
type StoreBridge struct{ s storeImpl }

func NewStoreBridge(s storeImpl) *StoreBridge { return &StoreBridge{s: s} }

func (b *StoreBridge) CreateExploration(ctx context.Context, taskID int64, goal string) (int64, error) {
	return b.s.db.CreateExploration(ctx, taskID, goal)
}
func (b *StoreBridge) GetExploration(ctx context.Context, id int64) (*agent.Exploration, error) {
	return b.s.db.GetExploration(ctx, id)
}
func (b *StoreBridge) GetTodolist(ctx context.Context, explorationID int64) ([]string, error) {
	return b.s.db.GetTodolist(ctx, explorationID)
}
func (b *StoreBridge) SetTodolist(ctx context.Context, explorationID int64, list []string) error {
	return b.s.db.SetTodolist(ctx, explorationID, list)
}
func (b *StoreBridge) SetExplorationStatus(ctx context.Context, id int64, status string) error {
	return b.s.db.SetExplorationStatus(ctx, id, status)
}
func (b *StoreBridge) CreateGoal(ctx context.Context, explorationID int64, title, desc string) (int64, error) {
	return b.s.db.CreateGoal(ctx, explorationID, title, desc)
}
func (b *StoreBridge) AddIntent(ctx context.Context, explorationID int64, title, desc string) (int64, error) {
	return b.s.db.AddIntent(ctx, explorationID, title, desc)
}
func (b *StoreBridge) CreateFact(ctx context.Context, explorationID int64, summary, status string, content map[string]any) (int64, error) {
	return b.s.db.CreateFact(ctx, explorationID, summary, status, content)
}
func (b *StoreBridge) CreateFindingNode(ctx context.Context, explorationID int64, title, severity string, evidence map[string]any) (int64, error) {
	return b.s.db.CreateFindingNode(ctx, explorationID, title, severity, evidence)
}
func (b *StoreBridge) ProveGoals(ctx context.Context, explorationID int64, goalIDs []int64) error {
	return b.s.db.ProveGoals(ctx, explorationID, goalIDs)
}
func (b *StoreBridge) SetNodeStatus(ctx context.Context, id int64, status string) error {
	return b.s.db.SetNodeStatus(ctx, id, status)
}
func (b *StoreBridge) ClaimNextIntent(ctx context.Context, explorationID int64, workerID string) (*agent.Node, error) {
	n, err := b.s.db.ClaimNextIntent(ctx, explorationID, workerID)
	if err != nil {
		return nil, err
	}
	if n == nil {
		return nil, nil
	}
	return n, nil
}
func (b *StoreBridge) AddEdge(ctx context.Context, explorationID, fromID, toID int64, relation string) error {
	return b.s.db.AddEdge(ctx, explorationID, fromID, toID, relation)
}
func (b *StoreBridge) Anchor(ctx context.Context, explorationID, nodeID, assetID int64) error {
	return b.s.db.Anchor(ctx, explorationID, nodeID, assetID)
}
func (b *StoreBridge) HasOpenIntent(ctx context.Context, explorationID int64) (bool, error) {
	return b.s.db.HasOpenIntent(ctx, explorationID)
}
func (b *StoreBridge) GetTask(ctx context.Context, id int64) (*agent.Task, error) {
	return b.s.db.GetTask(ctx, id)
}
func (b *StoreBridge) SetTaskStatus(ctx context.Context, id int64, status, errMsg string) error {
	return b.s.db.SetTaskStatus(ctx, id, status, errMsg)
}
func (b *StoreBridge) LogActivity(ctx context.Context, a agent.Activity) (int64, error) {
	return b.s.db.LogActivity(ctx, a)
}
func (b *StoreBridge) InsertAsset(ctx context.Context, companyID int64, a agent.Asset) (int64, bool, error) {
	return b.s.db.InsertAsset(ctx, companyID, a)
}
func (b *StoreBridge) SearchWorkerTraces(ctx context.Context, taskID int64, q string, limit int) ([]agent.Activity, error) {
	rows, err := b.s.db.SearchWorkerTraces(ctx, taskID, q, limit)
	if err != nil {
		return nil, err
	}
	out := make([]agent.Activity, len(rows))
	for i, r := range rows {
		out[i] = r
	}
	return out, nil
}
func (b *StoreBridge) GetWorkerTrace(ctx context.Context, intentID int64, limit int) ([]agent.Activity, error) {
	rows, err := b.s.db.GetWorkerTrace(ctx, intentID, limit)
	if err != nil {
		return nil, err
	}
	out := make([]agent.Activity, len(rows))
	for i, r := range rows {
		out[i] = r
	}
	return out, nil
}
func (b *StoreBridge) ReportFinding(ctx context.Context, f agent.Finding) (int64, bool, error) {
	return b.s.db.ReportFinding(ctx, f)
}
func (b *StoreBridge) EnqueueIntercept(ctx context.Context, p agent.PendingIntercept) (int64, error) {
	return b.s.db.EnqueueIntercept(ctx, p)
}
func (b *StoreBridge) GetPendingStatus(ctx context.Context, id int64) (string, error) {
	pi, err := b.s.db.GetPending(ctx, id)
	if err != nil {
		return "", err
	}
	return pi.Status, nil
}

// guardAdapter 把 intercept.Guard 适配成 agent.Guard
type guardAdapter struct{ g *intercept.Guard }

// guardAdapter 实现 agent.Guard
func (a *guardAdapter) Check(tool string, input map[string]any) (agent.Decision, error) {
	ctx := context.Background()
	d, err := a.g.Check(ctx, tool, input)
	if err != nil {
		return agent.Decision{}, err
	}
	return agent.Decision{Action: d.Action, RuleID: d.RuleID, Reason: d.Reason}, nil
}

// extractDomains 从文本提取域名
func extractDomains(s string) []string {
	re := regexp.MustCompile(`(?i)\b([a-z0-9][a-z0-9\-\.]*\.[a-z]{2,})\b`)
	seen := map[string]bool{}
	var out []string
	for _, m := range re.FindAllString(s, -1) {
		low := strings.ToLower(m)
		if !seen[low] {
			out = append(out, low)
			seen[low] = true
		}
	}
	return out
}

func firstDomain(s string) string {
	hosts := extractDomains(s)
	for _, h := range hosts {
		if strings.HasPrefix(h, "http") {
			continue
		}
		return h
	}
	if len(hosts) > 0 {
		return hosts[0]
	}
	return ""
}