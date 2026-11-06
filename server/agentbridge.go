package server

import (
	"context"
	"fmt"
	"net"
	"regexp"
	"strings"

	"pentigent/agent"
	"pentigent/db"
	"pentigent/intercept"
)

// agentGoalsRun 调用 goals agent 做目标分解 + 约束提取。
// 把操作员已登记的授权范围一并传给 LLM，让它如实复述——
// LLM 发明的新范围会被 scope 白名单丢弃，不如一开始就告诉它边界在哪。
func agentGoalsRun(ctx context.Context, task *db.Task, scope []db.ScopeItem) agent.GoalsResult {
	patterns := make([]string, 0, len(scope))
	for _, s := range scope {
		if s.Pattern != "" {
			patterns = append(patterns, s.Pattern)
		}
	}
	return agent.GoalsRun(ctx, task.Goal, task.Description, "", patterns)
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

// agentWorkerRun 运行一个 worker 直到意图完成。
// guard 必须是"每任务独立"的实例：共享会在并发任务间串味（B 的 scope 覆盖 A 的 scope → 越权）。
func agentWorkerRun(ctx context.Context, e *Engine, guard *intercept.Guard, taskID, explorationID int64, intent *db.Node) agent.WorkerResult {
	var companyID int64
	if task, err := e.db.GetTask(ctx, taskID); err == nil && task.CompanyID != nil {
		companyID = *task.CompanyID
	}
	w := &agent.Worker{
		Store:     NewStoreBridge(storeImpl{db: e.db}),
		Guard:     &guardAdapter{g: guard},
		CompanyID: companyID,
	}
	return w.Run(ctx, taskID, explorationID, intent, e.maxRounds)
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

// TouchIntent 心跳续约：worker 每轮刷新 running intent 的 claimed_at，
// 避免长意图被 ReclaimStuckIntents 误回收重领。
func (b *StoreBridge) TouchIntent(ctx context.Context, intentID int64) error {
	return b.s.db.TouchIntent(ctx, intentID)
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
func (b *StoreBridge) ExpirePending(ctx context.Context, id int64) error {
	return b.s.db.ExpirePending(ctx, id)
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

// ScopeAllows 资产入库前的范围校验（资产图是全局真值库，写入范围外目标等于越权建档）。
func (a *guardAdapter) ScopeAllows(host string) bool {
	return a.g.ScopeAllows(host)
}

// 明显不是主机名的后缀（文件名/编程语言/静态资源）。
// 任务描述里常出现 "node.js"、"report.md" 这类词，若被当成域名写进 scope，
// 会意外扩大授权范围，因此这里做保守过滤。
var nonHostSuffix = map[string]bool{
	"js": true, "ts": true, "jsx": true, "tsx": true, "py": true, "go": true,
	"md": true, "sh": true, "bat": true, "ps1": true, "exe": true, "dll": true,
	"txt": true, "json": true, "html": true, "htm": true, "css": true, "php": true,
	"jsp": true, "asp": true, "aspx": true, "sql": true, "yaml": true, "yml": true,
	"conf": true, "ini": true, "log": true, "tmp": true, "bak": true, "db": true,
	"png": true, "jpg": true, "jpeg": true, "gif": true, "ico": true, "svg": true,
	"xml": true, "csv": true, "pdf": true, "doc": true, "docx": true, "xls": true,
	"xlsx": true, "zip": true, "tar": true, "gz": true, "rar": true, "mp4": true,
	"mp3": true, "mov": true, "avi": true, "woff": true, "woff2": true, "ttf": true, "eot": true,
}

var nonHostExact = map[string]bool{
	"asp.net": true, "node.js": true, "vue.js": true, "react.js": true,
	"next.js": true, "express.js": true, "jquery.js": true, "d3.js": true,
	"three.js": true, "socket.io": true,
}

// isLikelyHost 过滤掉明显是文件名/技术名词的 token，避免误扩授权范围。
func isLikelyHost(s string) bool {
	if nonHostExact[s] {
		return false
	}
	i := strings.LastIndex(s, ".")
	if i <= 0 || i == len(s)-1 {
		return false
	}
	return !nonHostSuffix[s[i+1:]]
}

// extractDomains 从文本提取域名和 IP（授权范围推断用）。
func extractDomains(s string) []string {
	seen := map[string]bool{}
	var out []string
	add := func(v string) {
		v = strings.ToLower(strings.TrimSpace(v))
		if v == "" || seen[v] {
			return
		}
		out = append(out, v)
		seen[v] = true
	}

	// 域名
	re := regexp.MustCompile(`(?i)\b([a-z0-9][a-z0-9\-\.]*\.[a-z]{2,})\b`)
	for _, m := range re.FindAllString(s, -1) {
		if isLikelyHost(strings.ToLower(m)) {
			add(m)
		}
	}
	// IPv4（描述里直接写 IP 时也要推断进 scope）
	ipRe := regexp.MustCompile(`\b(\d{1,3}(?:\.\d{1,3}){3})\b`)
	for _, m := range ipRe.FindAllString(s, -1) {
		if net.ParseIP(m) != nil {
			add(m)
		}
	}
	// IPv6（含方括号写法）：先抓候选再校验，避免把时间戳当成地址
	ipv6Re := regexp.MustCompile(`\[[0-9a-fA-F:]+\]|(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}`)
	for _, m := range ipv6Re.FindAllString(s, -1) {
		cand := strings.Trim(m, "[]")
		if ip := net.ParseIP(cand); ip != nil && ip.To4() == nil {
			add(ip.String())
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
