package agent

import (
	"context"
	"encoding/json"
)

// ---- 对话消息 ----

type Role = string

const (
	RoleSystem    = "system"
	RoleUser      = "user"
	RoleAssistant = "assistant"
	RoleTool      = "tool"
)

type ToolCall struct {
	ID       string `json:"id"`
	Type     string `json:"type"` // function
	Index    *int   `json:"index,omitempty"`
	Function struct {
		Name      string `json:"name"`
		Arguments string `json:"arguments"` // JSON string
	} `json:"function"`
}

type Message struct {
	Role       Role       `json:"role"`
	Content    string     `json:"content,omitempty"`
	Name       string     `json:"name,omitempty"`
	ToolCallID string     `json:"tool_call_id,omitempty"`
	ToolCalls  []ToolCall `json:"tool_calls,omitempty"`
}

// ---- 工具 schema ----

type ToolParam struct {
	Type        string `json:"type"`
	Description string `json:"description,omitempty"`
	Enum        []any  `json:"enum,omitempty"`
	Items       any    `json:"items,omitempty"`
}

type Tool struct {
	Type     string                 `json:"type"`
	Function FunctionSchema         `json:"function"`
}

type FunctionSchema struct {
	Name        string               `json:"name"`
	Description string               `json:"description"`
	Parameters  map[string]ToolParam `json:"parameters"` // simplified; see raw
	Raw         any                  `json:"-"`
}

// ---- 请求 / 响应 ----

type ChatRequest struct {
	Model       string    `json:"model"`
	Messages    []Message `json:"messages"`
	Tools       []Tool    `json:"tools,omitempty"`
	ToolChoice  string    `json:"tool_choice,omitempty"` // auto | required | none
	MaxTokens   int       `json:"max_tokens,omitempty"`
	Temperature float64   `json:"temperature,omitempty"`
}

type Usage struct {
	InputTokens  int `json:"input_tokens"`
	OutputTokens int `json:"output_tokens"`
}

type ChatResponse struct {
	Content   string     `json:"content"`
	ToolCalls []ToolCall `json:"tool_calls"`
	Usage     Usage      `json:"usage"`
	Raw       any        `json:"-"`
}

// Provider LLM 接口（OpenAI 兼容）
type Provider interface {
	Chat(ctx context.Context, req ChatRequest) (ChatResponse, error)
	// Ping 探测连通性：返回可用描述，或错误说明不可用原因
	Ping(ctx context.Context) (string, error)
	Name() string
}

// Helper: 构造简化工具 schema
func ToolSchema(name, desc string, props map[string]any, required []string) Tool {
	p := map[string]any{"type": "object", "properties": props}
	if len(required) > 0 {
		p["required"] = required
	}
	return Tool{
		Type: "function",
		Function: FunctionSchema{
			Name:        name,
			Description: desc,
			Raw:         p,
		},
	}
}

func Prop(typ, desc string) map[string]any {
	return map[string]any{"type": typ, "description": desc}
}

// ParseArgs 解析 tool_call arguments JSON
func ParseArgs(raw string) (map[string]any, error) {
	var m map[string]any
	if raw == "" {
		return m, nil
	}
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		return nil, err
	}
	return m, nil
}