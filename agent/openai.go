package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"os"
	"strconv"
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
	ToolChoice  string    `json:"tool_choice,omitempty"`
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

// LLMError 结构化 LLM 错误（携带状态码 + Retry-After，便于精确退避）
type LLMError struct {
	StatusCode int
	RetryAfter time.Duration // 上游建议的重试等待（0=未知）
	Body       string
}

func (e *LLMError) Error() string {
	return fmt.Sprintf("llm error %d: %s", e.StatusCode, e.Body)
}

// IsRateLimit 是否限流（429）
func (e *LLMError) IsRateLimit() bool { return e.StatusCode == 429 }

// llmSem 限制全局并发 LLM 请求，避免多任务同时打爆上游（触发 502/限流）
var llmSem = make(chan struct{}, 3)

// Chat 发送一次 chat/completions；对可重试错误（5xx/429/网络）做指数退避重试
func (p *OpenAIProvider) Chat(ctx context.Context, req ChatRequest) (ChatResponse, error) {
	// 获取并发令牌
	select {
	case llmSem <- struct{}{}:
		defer func() { <-llmSem }()
	case <-ctx.Done():
		return ChatResponse{}, ctx.Err()
	}

	const maxAttempts = 4
	var lastErr error
	for attempt := 0; attempt < maxAttempts; attempt++ {
		resp, err := p.chatOnce(ctx, req)
		if err == nil {
			return resp, nil
		}
		lastErr = err
		if !retryableLLMError(err) || attempt == maxAttempts-1 {
			break
		}
		// 退避策略：
		//  - 限流(429)：按 Retry-After 或 30s 起步（分钟级限流，秒级重试无意义）
		//  - 其他可重试：1s / 2s / 4s 指数退避
		var backoff time.Duration
		var le *LLMError
		if errors.As(err, &le) && le.IsRateLimit() {
			backoff = le.RetryAfter
			if backoff <= 0 {
				backoff = 30 * time.Second
			}
			backoff *= time.Duration(1 + attempt) // 多次重试进一步拉长
		} else {
			backoff = time.Duration(1<<attempt) * time.Second
		}
		jitter := time.Duration(rand.Int63n(int64(500 * time.Millisecond)))
		select {
		case <-ctx.Done():
			return ChatResponse{}, ctx.Err()
		case <-time.After(backoff + jitter):
		}
	}
	return ChatResponse{}, lastErr
}

// retryableLLMError 判断是否值得重试（上游临时故障 / 限流 / 网络抖动）
func retryableLLMError(err error) bool {
	if err == nil {
		return false
	}
	var le *LLMError
	if errors.As(err, &le) {
		// 4xx 除 429 外不重试（key/参数问题重试也没用）
		if le.StatusCode >= 400 && le.StatusCode < 500 && le.StatusCode != 429 {
			return false
		}
		return true
	}
	msg := err.Error()
	// 网络 / 超时 / 解码
	return strings.Contains(msg, "llm request") || strings.Contains(msg, "timeout") ||
		strings.Contains(msg, "deadline") || strings.Contains(msg, "llm decode") ||
		strings.Contains(msg, "EOF") || strings.Contains(msg, "connection reset")
}

func (p *OpenAIProvider) chatOnce(ctx context.Context, req ChatRequest) (ChatResponse, error) {
	if p.apiKey == "" {
		return ChatResponse{}, fmt.Errorf("OPENAI_API_KEY 未设置：真实 provider 需要 key，无 key 请使用 mock 模式")
	}
	model := req.Model
	if model == "" {
		model = p.model
	}
	// 组装 tools：Function.Raw 只是 parameters 定义，这里必须补上 name/description，
	// 否则上游收到没有函数名的 tool，会直接拒绝（502）。
	var tools []any
	for _, t := range req.Tools {
		fn := map[string]any{
			"name":        t.Function.Name,
			"description": t.Function.Description,
		}
		if t.Function.Raw != nil {
			fn["parameters"] = t.Function.Raw
		} else {
			fn["parameters"] = map[string]any{"type": "object", "properties": map[string]any{}}
		}
		tools = append(tools, map[string]any{
			"type":     "function",
			"function": fn,
		})
	}
	body := openAIChatRequest{
		Model:       model,
		Messages:    req.Messages,
		Tools:       tools,
		ToolChoice:  req.ToolChoice,
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
		le := &LLMError{StatusCode: resp.StatusCode, Body: string(data)}
		// 读 Retry-After（秒数形式，限流时上游通常会带）
		if ra := resp.Header.Get("Retry-After"); ra != "" {
			if secs, err := strconv.Atoi(ra); err == nil && secs > 0 {
				le.RetryAfter = time.Duration(secs) * time.Second
			}
		}
		return ChatResponse{}, le
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