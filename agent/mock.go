package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

// MockProvider 内置假 LLM：无 key 也能跑通 planner/worker 全闭环。
// 它是"确定性智能体"，按 STATE 块驱动脚本，行为贴近真实渗透流程。
type MockProvider struct {
	session map[string]*mockSession // key: explorationID or workerID/nodeID
}

type mockSession struct {
	calls int
	plan  []mockStep
	idx   int
}

type mockStep struct {
	name    string
	args    map[string]any
	content string
}

func NewMockProvider() *MockProvider {
	return &MockProvider{session: map[string]*mockSession{}}
}

func (p *MockProvider) Name() string { return "mock" }

// Ping mock 无需外部依赖，直接返回可用
func (p *MockProvider) Ping(ctx context.Context) (string, error) {
	return "mock (无需 API key)", nil
}

var (
	reState     = regexp.MustCompile(`STATE\s*[:=]\s*(\{.*\})`)
	reTarget    = regexp.MustCompile(`(?i)(?:target|scope|host|domain)[:=]\s*\"?([a-z0-9\-\.]+\.[a-z]{2,})\"?`)
	reIntent    = regexp.MustCompile(`(?i)intent[^\n]{0,80}[:：]\s*(.{1,120})`)
	reURL       = regexp.MustCompile(`https?://[^\s"'` + "`" + `]+`)
	reToolResult = regexp.MustCompile(`^result\((\w+)\): (.+)$`)
	reAnyHost   = regexp.MustCompile(`(?i)([a-z0-9][a-z0-9\-\.]*\.[a-z]{2,})\b`)
)

// firstHostInMessages 从消息里抓第一个像域名的东西
func firstHostInMessages(messages []Message) string {
	// 优先取目标/授权范围里的显式标注
	for _, m := range messages {
		if m.Role == RoleUser || m.Role == RoleSystem {
			if t := reTarget.FindStringSubmatch(m.Content); t != nil {
				return strings.ToLower(t[1])
			}
		}
	}
	// 否则找任意域名（跳过长单词）
	for _, m := range messages {
		if m.Role == RoleUser || m.Role == RoleSystem {
			for _, h := range reAnyHost.FindAllString(m.Content, -1) {
				low := strings.ToLower(h)
				if strings.Contains(low, ".com") || strings.Contains(low, ".net") || strings.Contains(low, ".org") || strings.Contains(low, ".cn") || strings.Contains(low, ".io") {
					return low
				}
			}
		}
	}
	return ""
}

type mockState struct {
	Goal         string `json:"goal"`
	Target       string `json:"target"`
	OpenIntents  int    `json:"open_intents"`
	DoneIntents  int    `json:"done_intents"`
	Facts        int    `json:"facts"`
	Findings     int    `json:"findings"`
	GoalsMet     bool   `json:"goals_met"`
	FirstCall    bool   `json:"first_call"`
}

func parseState(messages []Message) mockState {
	var st mockState
	// 取最后一个 user/system 内容探测 STATE
	for i := len(messages) - 1; i >= 0; i-- {
		m := messages[i]
		if m.Role != RoleUser && m.Role != RoleSystem {
			continue
		}
		if mm := reState.FindStringSubmatch(m.Content); mm != nil {
			_ = json.Unmarshal([]byte(mm[1]), &st)
			return st
		}
	}
	// fallback：从 goal 文本抽 target
	for _, m := range messages {
		if m.Role == RoleUser {
			if t := reTarget.FindStringSubmatch(m.Content); t != nil {
				st.Target = t[1]
			}
		}
	}
	return st
}

func detectRole(messages []Message) string {
	for _, m := range messages {
		if m.Role == RoleSystem {
			low := strings.ToLower(m.Content)
			switch {
			case strings.Contains(low, "planner"):
				return "planner"
			case strings.Contains(low, "worker"):
				return "worker"
			}
		}
	}
	return "main"
}

func countAssistantToolCalls(messages []Message) int {
	n := 0
	for _, m := range messages {
		if m.Role == RoleAssistant && len(m.ToolCalls) > 0 {
			n++
		}
	}
	return n
}

// lastToolResult 取最近的 tool role 消息内容
func lastToolResult(messages []Message) string {
	for i := len(messages) - 1; i >= 0; i-- {
		if messages[i].Role == RoleTool {
			return messages[i].Content
		}
	}
	return ""
}

func (p *MockProvider) Chat(ctx context.Context, req ChatRequest) (ChatResponse, error) {
	role := detectRole(req.Messages)
	st := parseState(req.Messages)
	if st.Target == "" {
		st.Target = firstHostInMessages(req.Messages)
	}
	if st.Target == "" {
		st.Target = "example.com"
	}

	// 估算 token 消耗（中文按字，其余按 4 字符 ≈ 1 token）
	in := 0
	out := 0
	for _, m := range req.Messages {
		in += estimateTokens(m.Content)
		for _, t := range m.ToolCalls {
			in += estimateTokens(t.Function.Arguments)
		}
	}

	var resp ChatResponse
	switch role {
	case "planner":
		resp = p.planStratum(req, st)
	case "worker":
		resp = p.workStratum(req, st)
	default:
		resp = p.goalsStratum(req, st)
	}
	for _, t := range resp.ToolCalls {
		out += estimateTokens(t.Function.Arguments)
	}
	out += estimateTokens(resp.Content)
	resp.Usage = Usage{InputTokens: in, OutputTokens: out}
	return resp, nil
}

// estimateTokens 粗略 token 估算
func estimateTokens(s string) int {
	total := 0
	for _, r := range s {
		if r > 127 {
			total++
		} else {
			total++
		}
	}
	// 中文字符大致 1 token/字，ASCII 4 字符 ≈ 1 token
	return total/4 + 1
}

// ================= 剧本注册表 =================
// 让 mock 每次任务有变化：按目标域名哈希稳定挑选剧本（同目标可复现，不同目标多样）。

type mockScript struct {
	Name        string
	VulnTitle   string
	VulnSeverity string
	VulnEvidence map[string]any
	Intents     []map[string]any // add_intent 序列
}

var mockScripts = []mockScript{
	{
		Name: "admin-panel", VulnTitle: "管理后台未受访问控制保护", VulnSeverity: "high",
		VulnEvidence: map[string]any{"note": "探测到可访问的管理入口"},
	},
	{
		Name: "exposed-git", VulnTitle: ".git 目录信息泄露", VulnSeverity: "medium",
		VulnEvidence: map[string]any{"note": "探测到 .git 目录可访问"},
	},
	{
		Name: "open-redirect", VulnTitle: "开放重定向", VulnSeverity: "low",
		VulnEvidence: map[string]any{"note": "存在可被利用的跳转参数"},
	},
	{
		Name: "info-disclosure", VulnTitle: "敏感信息泄露（报错堆栈）", VulnSeverity: "medium",
		VulnEvidence: map[string]any{"note": "错误页泄露内部路径与版本"},
	},
	{
		Name: "weak-login", VulnTitle: "弱口令登录入口", VulnSeverity: "high",
		VulnEvidence: map[string]any{"note": "存在可枚举的登录接口"},
	},
}

// pickScript 按目标域名哈希选剧本（稳定：同 target 永远同一剧本）
func pickScript(target string) mockScript {
	h := 0
	for _, c := range target {
		h = (h*31 + int(c)) % 100000
	}
	return mockScripts[h%len(mockScripts)]
}

// scriptIntents 由剧本生成意图序列
func scriptIntents(s mockScript, target string) []map[string]any {
	host := target
	return []map[string]any{
		{"title": fmt.Sprintf("枚举 %s 的子域名与服务", host), "description": "通过 DNS 和 HTTP 指纹确定资产面"},
		{"title": fmt.Sprintf("对 %s 的服务做端口与版本探测", host), "description": "识别开放端口与服务版本"},
		{"title": fmt.Sprintf("检查 %s 的 Web 服务漏洞", host), "description": fmt.Sprintf("探测 %s 相关漏洞", s.Name)},
		{"title": fmt.Sprintf("验证 %s 的漏洞利用链", host), "description": "对已发现问题做验证"},
	}
}

// vulnPath 剧本对应的探测路径
func vulnPath(s mockScript) string {
	switch s.Name {
	case "admin-panel":
		return "admin"
	case "exposed-git":
		return ".git/HEAD"
	case "open-redirect":
		return "redirect?url=https://evil.com"
	case "info-disclosure":
		return "nonexistent-page"
	case "weak-login":
		return "login"
	default:
		return "admin"
	}
}

// ================= 目标分解（main / goals） =================

func (p *MockProvider) goalsStratum(req ChatRequest, st mockState) ChatResponse {
	if numToolCallsSoFar(req.Messages, "set_goals") > 0 {
		return ChatResponse{Content: "目标与约束已登记完成。"}
	}
	target := st.Target
	scr := pickScript(target)
	return ChatResponse{
		ToolCalls: []ToolCall{
			tc("set_goals", map[string]any{
				"goals": []any{
					map[string]any{"title": fmt.Sprintf("探测 %s 的资产面", target), "description": "枚举子域名/端口/Web 服务"},
					map[string]any{"title": fmt.Sprintf("发现 %s 的 %s 漏洞", target, scr.Name), "description": fmt.Sprintf("针对 %s 场景做漏洞检查", scr.Name)},
				},
			}),
			tc("add_task_scope", map[string]any{"scope": []any{target}, "kind": "domain"}),
			tc("set_constraints", map[string]any{
				"deny": []any{"rm -rf", "shutdown", "/etc/shadow", "169.254.169.254"},
			}),
		},
	}
}

// ================= Planner 层 =================

func (p *MockProvider) planStratum(req ChatRequest, st mockState) ChatResponse {
	// 已 prove → 停止
	if st.GoalsMet {
		return ChatResponse{Content: "目标已达成。"}
	}
	// frontier 还有待办 → 等 worker 消化（下次唤醒再评估）
	if st.OpenIntents > 0 {
		return ChatResponse{Content: "无新方向，等待 worker 消化。"}
	}
	// 全部 intent 已 done 且没有 open → prove
	if st.DoneIntents >= 4 {
		return ChatResponse{
			Content: "目标已达成。",
			ToolCalls: []ToolCall{
				tc("prove_goal", map[string]any{"goal_ids": []int64{}, "summary": "资产面与漏洞检查已完成"}),
			},
		}
	}
	// 按序派事件线：一次派完剩余独立意图，让 N 个 worker 并发领取
	target := st.Target
	plan := scriptIntents(pickScript(target), target)
	var calls []ToolCall
	for i := st.DoneIntents; i < len(plan); i++ {
		calls = append(calls, tc("add_intent", plan[i]))
	}
	if len(calls) > 0 {
		return ChatResponse{ToolCalls: calls}
	}
	return ChatResponse{Content: "done"}
}

// ================= Worker 层 =================

func (p *MockProvider) workStratum(req ChatRequest, st mockState) ChatResponse {
	// 已有动作回合 → 看 tool result 决定下一步
	doneTurns := countAssistantToolCalls(req.Messages)
	intentTitle := extractIntent(req.Messages)
	lower := strings.ToLower(intentTitle)

	type planT struct {
		name    string
		args    map[string]any
		content string
	}
	var script []planT
	host := st.Target
	markDone := ""
	switch {
	case strings.Contains(lower, "子域名") || strings.Contains(lower, "枚举"):
		script = []planT{
			{name: "bash", args: map[string]any{"command": fmt.Sprintf("nslookup -type=A %s 2>&1", host)}},
			{name: "webfetch", args: map[string]any{"url": fmt.Sprintf("https://%s", host)}},
			{name: "insert_assets", args: map[string]any{
				"assets": []any{
					map[string]any{"type": "root_domain", "domain": host},
					map[string]any{"type": "service", "url": fmt.Sprintf("https://%s", host), "title": "Web 服务"},
				},
			}},
			{name: "record_fact", args: map[string]any{"summary": fmt.Sprintf("发现并确认目标根域 %s 及 Web 服务可达", host)}},
		}
		markDone = "目标 %s 资产枚举完成"
	case strings.Contains(lower, "端口") || strings.Contains(lower, "版本"):
		script = []planT{
			{name: "bash", args: map[string]any{"command": fmt.Sprintf("curl.exe -s -m 5 -o NUL -w \"%%{http_code}\" http://%s/", host)}},
			{name: "record_fact", args: map[string]any{"summary": "扫描开放端口，识别服务指纹"}},
		}
		markDone = "端口与版本探测完成"
	case strings.Contains(lower, "漏洞") || strings.Contains(lower, "web"):
		scr := pickScript(host)
		script = []planT{
			{name: "webfetch", args: map[string]any{"url": fmt.Sprintf("https://%s/robots.txt", host)}},
			{name: "webfetch", args: map[string]any{"url": fmt.Sprintf("https://%s/%s", host, vulnPath(scr))}},
			{name: "record_fact", args: map[string]any{"summary": "Web 服务常见路径与弱配置探测完成"}},
			{name: "report_finding", args: map[string]any{
				"title":    scr.VulnTitle,
				"severity": scr.VulnSeverity,
				"evidence": map[string]any{
					"url":  fmt.Sprintf("https://%s/%s", host, vulnPath(scr)),
					"note": scr.VulnEvidence["note"],
				},
			}},
		}
		markDone = "Web 漏洞检查完成"
	case strings.Contains(lower, "验证") || strings.Contains(lower, "利用"):
		script = []planT{
			{name: "webfetch", args: map[string]any{"url": fmt.Sprintf("https://%s/login", host)}},
			// POST 探测：会触发 ask-write-method 规则 → 进人工审批队列，演示审批门
			{name: "webfetch", args: map[string]any{"url": fmt.Sprintf("https://%s/login", host), "method": "POST"}},
			{name: "record_fact", args: map[string]any{"summary": "针对发现的凭证/端点做可验证测试"}},
		}
		markDone = "验证链完成"
	default:
		// 未知意图 —— 降级为一次安全探测
		script = []planT{
			{name: "bash", args: map[string]any{"command": fmt.Sprintf("curl.exe -s -m 6 -o NUL -w \"%%{http_code}\" https://%s/", host)}},
			{name: "record_fact", args: map[string]any{"summary": fmt.Sprintf("探测 %s 可达性", host)}},
		}
		markDone = "探测完成"
	}

	// 已用完脚本 → 结束，返回总结
	if doneTurns >= len(script) {
		return ChatResponse{Content: fmt.Sprintf(markDone, host)}
	}
	step := script[doneTurns]
	return ChatResponse{ToolCalls: []ToolCall{tc(step.name, step.args)}}
}

// ================= 工具构造 =================

func tc(name string, args map[string]any) ToolCall {
	var t ToolCall
	t.ID = fmt.Sprintf("call_mock_%s_%d", name, hashName())
	t.Type = "function"
	t.Function.Name = name
	b, _ := json.Marshal(args)
	t.Function.Arguments = string(b)
	return t
}

var mockSeq int

func hashName() int {
	mockSeq++
	return mockSeq
}

func numToolCallsSoFar(messages []Message, name string) int {
	n := 0
	for _, m := range messages {
		if m.Role == RoleAssistant {
			for _, t := range m.ToolCalls {
				if t.Function.Name == name {
					n++
				}
			}
		}
	}
	return n
}

func extractIntent(messages []Message) string {
	// 1. 意图标题前缀（worker 用户消息格式）
	for i := len(messages) - 1; i >= 0; i-- {
		if messages[i].Role != RoleUser {
			continue
		}
		if mm := regexp.MustCompile(`(?m)^\s*意图标题\s*[:：]\s*(.{1,120})`).FindStringSubmatch(messages[i].Content); mm != nil {
			return strings.TrimSpace(mm[1])
		}
		if mm := reIntent.FindStringSubmatch(messages[i].Content); mm != nil {
			return strings.TrimSpace(mm[1])
		}
		// 找 "title":"..." 形式
		if mm := regexp.MustCompile(`title["']?\s*[:=]\s*["']([^"']+)`).FindStringSubmatch(messages[i].Content); mm != nil {
			return mm[1]
		}
	}
	return "未知意图"
}