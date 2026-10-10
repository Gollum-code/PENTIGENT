package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// OpenAIProvider 实现 OpenAI 兼容 Chat Completions（非流式）
type OpenAIProvider struct {
	name    string
	baseURL string
	model   string
	apiKey  string
	client  *http.Client
}

type openAIChatRequest struct {
	Model       string    `json:"model"`
	Messages    []Message `json:"messages"`
	Tools       []any     `json:"tools,omitempty"`
	MaxTokens   int       `json:"max_tokens,omitempty"`
	Temperature float64   `json:"temperature,omitempty"`
}

type openAIChoice struct {
	Message struct {
		Content   string     `json:"content"`
		ToolCalls []ToolCall `json:"tool_calls"`
	} `json:"message"`
}

type openAIResponse struct {
	Choices []openAIChoice `json:"choices"`
	Usage   struct {
		PromptTokens     int `json:"prompt_tokens"`
		CompletionTokens int `json:"completion_tokens"`
	} `json:"usage"`
	Error *struct {
		Message string `json:"message"`
		Type    string `json:"type"`
	} `json:"error"`
}

// NewOpenAIProvider baseURL/model 为空时退化到环境变量
func NewOpenAIProvider(name, baseURL, model string) *OpenAIProvider {
	if baseURL == "" {
		baseURL = os.Getenv("OPENAI_BASE_URL")
	}
	if baseURL == "" {
		baseURL = "https://api.openai.com/v1"
	}
	if model == "" {
		model = os.Getenv("OPENAI_MODEL")
	}
	if model == "" {
		model = "gpt-4o-mini"
	}
	return &OpenAIProvider{
		name:    name,
		baseURL: strings.TrimRight(baseURL, "/"),
		model:   model,
		apiKey:  os.Getenv("OPENAI_API_KEY"),
		client:  &http.Client{Timeout: 2 * time.Minute},
	}
}

func (p *OpenAIProvider) Name() string { return p.name }

func (p *OpenAIProvider) Model() string { return p.model }

func (p *OpenAIProvider) HasKey() bool { return p.apiKey != "" }

// Ping 探测真实 LLM 连通性：发一个最小请求，确认 key/端点/模型可用
func (p *OpenAIProvider) Ping(ctx context.Context) (string, error) {
	if p.apiKey == "" {
		return "", fmt.Errorf("未设置 OPENAI_API_KEY")
	}
	_, err := p.Chat(ctx, ChatRequest{
		Messages:  []Message{{Role: RoleUser, Content: "ping"}},
		MaxTokens: 5,
	})
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s @ %s", p.model, p.baseURL), nil
}

func (p *OpenAIProvider) Chat(ctx context.Context, req ChatRequest) (ChatResponse, error) {
	if p.apiKey == "" {
		return ChatResponse{}, fmt.Errorf("OPENAI_API_KEY 未设置：真实 provider 需要 key，无 key 请使用 mock 模式")
	}
	model := req.Model
	if model == "" {
		model = p.model
	}
	var tools []any
	for _, t := range req.Tools {
		if t.Function.Raw != nil {
			tools = append(tools, map[string]any{
				"type":     "function",
				"function": t.Function.Raw,
			})
		}
	}
	body := openAIChatRequest{
		Model:       model,
		Messages:    req.Messages,
		Tools:       tools,
		MaxTokens:   req.MaxTokens,
		Temperature: req.Temperature,
	}
	raw, _ := json.Marshal(body)
	httpReq, err := http.NewRequestWithContext(ctx, "POST", p.baseURL+"/chat/completions", bytes.NewReader(raw))
	if err != nil {
		return ChatResponse{}, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+p.apiKey)

	resp, err := p.client.Do(httpReq)
	if err != nil {
		return ChatResponse{}, fmt.Errorf("llm request: %w", err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return ChatResponse{}, err
	}
	if resp.StatusCode != 200 {
		return ChatResponse{}, fmt.Errorf("llm error %d: %s", resp.StatusCode, string(data))
	}
	var decoded openAIResponse
	if err := json.Unmarshal(data, &decoded); err != nil {
		return ChatResponse{}, fmt.Errorf("llm decode: %w", err)
	}
	if decoded.Error != nil {
		return ChatResponse{}, fmt.Errorf("llm error: %s", decoded.Error.Message)
	}
	out := ChatResponse{Raw: decoded}
	if len(decoded.Choices) > 0 {
		out.Content = decoded.Choices[0].Message.Content
		out.ToolCalls = decoded.Choices[0].Message.ToolCalls
	}
	out.Usage.InputTokens = decoded.Usage.PromptTokens
	out.Usage.OutputTokens = decoded.Usage.CompletionTokens
	return out, nil
}