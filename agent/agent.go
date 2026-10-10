package agent

// Guard 审批门接口（server 实现）
type Guard interface {
	// Check 返回工具调用决策
	Check(tool string, input map[string]any) (Decision, error)
}

type Decision struct {
	Action string // allow | deny | ask
	RuleID *int64
	Reason string
}

// ToolExecutor 执行过 guard 的 worker 工具（engine 注入）
type Executor interface {
	// Execute 执行单个工具调用，返回结果内容（会作为 tool message 回注 LLM）
	Execute(call ToolCall, nodeID int64, taskID int64) (string, error)
}

// Agent 统一 agent 结构：持有 provider 与干预回调
type Agent struct {
	Provider Provider
	Role     string // main | planner | worker
}