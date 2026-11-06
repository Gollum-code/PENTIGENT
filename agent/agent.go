package agent

// Guard 审批门接口（server 实现）
type Guard interface {
	// Check 返回工具调用决策
	Check(tool string, input map[string]any) (Decision, error)
	// ScopeAllows 判断 host 是否在任务授权范围内（写资产图时做范围校验）
	ScopeAllows(host string) bool
}

type Decision struct {
	Action string // allow | deny | ask
	RuleID *int64
	Reason string
}
