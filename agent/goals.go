package agent

import (
	"context"
	"encoding/json"
	"fmt"
)

const goalsSystemPrompt = `You are the entry Agent (Main) of an authorized penetration-testing system.

A task has just been created. Break it down by CALLING TOOLS — plain text replies are ignored:
1) set_goals        : decompose the objective into 1..3 verifiable sub-goals
2) add_task_scope   : register the authorized target scope (hard boundary) from what the operator provided
3) set_constraints  : register operator deny/allow constraints (dangerous ops)

Call these tools once and finish. Do not perform any recon here.`

type Goal struct {
	Title       string `json:"title"`
	Description string `json:"description"`
}

type GoalsResult struct {
	Goals         []Goal
	Scope         []ScopeEntry
	Constraints   []ConstraintEntry
	InputTokens   int
	OutputTokens  int
	Error         string
}

type ScopeEntry struct {
	Pattern string `json:"pattern"`
	Kind    string `json:"kind"`
}

type ConstraintEntry struct {
	Kind    string `json:"kind"` // allow | deny
	Pattern string `json:"pattern"`
}

// GoalsRun 目标分解 + 约束提取
func GoalsRun(ctx context.Context, taskGoal, taskDesc, company string, scopePatterns []string) GoalsResult {
	res := GoalsResult{}

	tools := []Tool{}
	for _, name := range []string{"set_goals", "add_task_scope", "set_constraints"} {
		if t, ok := ToolByName(name); ok {
			tools = append(tools, t)
		}
	}

	userMsg := fmt.Sprintf("任务目标：%s\n任务描述：%s\n目标公司：%s\n已知授权范围：%v\n请分解目标并登记边界。",
		taskGoal, taskDesc, company, scopePatterns)

	messages := []Message{
		{Role: RoleSystem, Content: goalsSystemPrompt},
		{Role: RoleUser, Content: userMsg},
	}

	provider := CurrentProvider()
	resp, err := provider.Chat(ctx, ChatRequest{
		Messages:    messages,
		Tools:       tools,
		ToolChoice:  "required", // goals 必须调工具完成登记
		MaxTokens:   2048,
		Temperature: 0.2,
	})
	if err != nil {
		res.Error = err.Error()
		return res
	}
	res.InputTokens = resp.Usage.InputTokens
	res.OutputTokens = resp.Usage.OutputTokens

	for _, call := range resp.ToolCalls {
		args, err := ParseArgs(call.Function.Arguments)
		if err != nil {
			continue
		}
		switch call.Function.Name {
		case "set_goals":
			rawGoals, _ := args["goals"].([]any)
			for _, g := range rawGoals {
				gm, _ := g.(map[string]any)
				title, _ := gm["title"].(string)
				desc, _ := gm["description"].(string)
				res.Goals = append(res.Goals, Goal{Title: title, Description: desc})
			}
		case "add_task_scope":
			scope, _ := args["scope"].([]any)
			kind, _ := args["kind"].(string)
			if kind == "" {
				kind = "domain"
			}
			for _, s := range scope {
				if str, ok := s.(string); ok && str != "" {
					res.Scope = append(res.Scope, ScopeEntry{Pattern: str, Kind: kind})
				}
			}
		case "set_constraints":
			denies, _ := args["deny"].([]any)
			allows, _ := args["allow"].([]any)
			for _, d := range denies {
				if str, ok := d.(string); ok && str != "" {
					res.Constraints = append(res.Constraints, ConstraintEntry{Kind: "deny", Pattern: str})
				}
			}
			for _, a := range allows {
				if str, ok := a.(string); ok && str != "" {
					res.Constraints = append(res.Constraints, ConstraintEntry{Kind: "allow", Pattern: str})
				}
			}
		}
	}
	return res
}

// MarshalScopes 便于序列化
func MarshalScopes(scopes []ScopeEntry) string {
	b, _ := json.Marshal(scopes)
	return string(b)
}