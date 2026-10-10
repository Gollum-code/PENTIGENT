package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strings"
)

type Planner struct{}

// NewPlanner 占位（实际 db.Store 在 engine 侧注入）
func NewPlanner() *Planner { return &Planner{} }

const plannerSystemPrompt = `你是渗透测试系统的 Planner（规划者）。
你是**唯一**能生成意图(intent)的角色。
每次唤醒你会看到探索图态势 STATE。请判断：
1) 目标是否已达成 → 若达成调用 prove_goal；
2) 是否存在"新方向"值得推进 → 只对真正的新方向调用 add_intent 派 0..N 条意图进 frontier；
3) 若 frontier 已满 / 无新方向 → 不调用工具，表示等待或结束。

注意：跨唤醒共享 todolist 记录了整体攻击链的推进顺序；
串行利用链（发现注入点→取凭据→横向→提权）请记一次，按依赖逐步派，不要一次全派完。

STATE 是机器可读的态势快照：goal / target / open_intents / done_intents / facts / findings / goals_met。`

type PlannerState struct {
	Goal        string `json:"goal"`
	Target      string `json:"target"`
	OpenIntents int    `json:"open_intents"`
	DoneIntents int    `json:"done_intents"`
	Facts       int    `json:"facts"`
	Findings    int    `json:"findings"`
	GoalsMet    bool   `json:"goals_met"`
}

// PlanResult 一次 planner 唤醒的产出
type PlanResult struct {
	NewIntents    []int64  // 新建的 intent 节点 id
	NewIntentText []string // 新建意图的标题，用于写回 todolist
	GoalProved    bool
	Actions       []string
	InputTokens   int
	OutputTokens  int
	Error         string
}

// Run 执行一次 planner 唤醒：
// 读取态势 + 跨唤醒 todolist → 调 LLM → 处理 add_intent / prove_goal
func (pl *Planner) Run(ctx context.Context, store Store, explorationID int64, state PlannerState) PlanResult {
	res := PlanResult{}

	tools := []Tool{}
	for _, name := range []string{"add_intent", "prove_goal"} {
		if t, ok := ToolByName(name); ok {
			tools = append(tools, t)
		}
	}

	// 跨唤醒共享记忆：读回上一次唤醒的 todolist
	todolist, err := store.GetTodolist(ctx, explorationID)
	if err != nil {
		todolist = []string{}
	}

	stateJSON, _ := json.Marshal(state)
	todoJSON, _ := json.Marshal(todolist)
	userMsg := fmt.Sprintf(`当前探索态势：
STATE: %s

跨唤醒共享 todolist（已完成/已规划的动作，不要重复）：
%s

请决策：派新意图、证明目标、或等待。`,
		string(stateJSON), string(todoJSON))

	messages := []Message{
		{Role: RoleSystem, Content: plannerSystemPrompt},
		{Role: RoleUser, Content: userMsg},
	}

	provider := CurrentProvider()
	resp, err := provider.Chat(ctx, ChatRequest{
		Messages:    messages,
		Tools:       tools,
		MaxTokens:   2048,
		Temperature: 0.3,
	})
	if err != nil {
		res.Error = err.Error()
		return res
	}
	res.InputTokens = resp.Usage.InputTokens
	res.OutputTokens = resp.Usage.OutputTokens

	// 处理工具调用
	for _, call := range resp.ToolCalls {
		args, err := ParseArgs(call.Function.Arguments)
		if err != nil {
			res.Actions = append(res.Actions, fmt.Sprintf("%s 参数解析失败", call.Function.Name))
			continue
		}
		switch call.Function.Name {
		case "add_intent":
			title, _ := args["title"].(string)
			desc, _ := args["description"].(string)
			nodeID, err := store.AddIntent(ctx, explorationID, title, desc)
			if err != nil {
				res.Actions = append(res.Actions, "add_intent 失败: "+err.Error())
				continue
			}
			res.NewIntents = append(res.NewIntents, nodeID)
			res.NewIntentText = append(res.NewIntentText, title)
			res.Actions = append(res.Actions, "add_intent: "+title)

		case "prove_goal":
			ids, _ := args["goal_ids"].([]any)
			goalIDs := make([]int64, 0, len(ids))
			for _, v := range ids {
				if f, ok := v.(float64); ok {
					goalIDs = append(goalIDs, int64(f))
				}
			}
			if err := store.ProveGoals(ctx, explorationID, goalIDs); err != nil {
				res.Actions = append(res.Actions, "prove_goal 失败: "+err.Error())
				continue
			}
			res.GoalProved = true
			res.Actions = append(res.Actions, "prove_goal")
		}
	}
	return res
}

// UpdateTodolist 跨唤醒共享记忆：把本次新增的动作批量追加进 todolist（一次读一次写，去重）
func (pl *Planner) UpdateTodolist(ctx context.Context, store Store, explorationID int64, actions []string) {
	if len(actions) == 0 {
		return
	}
	list, err := store.GetTodolist(ctx, explorationID)
	if err != nil {
		log.Printf("planner: read todolist: %v", err)
		return
	}
	existing := make(map[string]bool, len(list))
	for _, item := range list {
		existing[item] = true
	}
	added := false
	for _, a := range actions {
		if a == "" || existing[a] {
			continue
		}
		existing[a] = true
		list = append(list, a)
		added = true
	}
	if !added {
		return
	}
	if err := store.SetTodolist(ctx, explorationID, list); err != nil {
		log.Printf("planner: write todolist: %v", err)
	}
}

// FormatIntents 便于调试
func FormatIntents(ids []int64) string {
	parts := make([]string, len(ids))
	for i, id := range ids {
		parts[i] = fmt.Sprintf("%d", id)
	}
	return strings.Join(parts, ",")
}