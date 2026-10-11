package agent

import (
	"strings"
	"testing"
)

// ---- Provider 行为 ----

func TestParseArgs(t *testing.T) {
	m, err := ParseArgs(`{"url":"https://x.com","method":"POST"}`)
	if err != nil {
		t.Fatal(err)
	}
	if m["url"] != "https://x.com" || m["method"] != "POST" {
		t.Errorf("解析错误: %+v", m)
	}
	// 空串 → 空 map 而非报错
	m2, err := ParseArgs("")
	if err != nil || len(m2) != 0 {
		t.Errorf("空参数应返回空 map: %+v err=%v", m2, err)
	}
	// 非法 JSON → 报错
	if _, err := ParseArgs("{bad"); err == nil {
		t.Error("非法 JSON 应报错")
	}
}

func TestEstimateTokensPositive(t *testing.T) {
	if got := estimateTokens(""); got < 1 {
		t.Errorf("空串也应至少 1 token, got %d", got)
	}
	short := estimateTokens("abc")
	long := estimateTokens(strings.Repeat("a", 400))
	if long <= short {
		t.Errorf("长文本 token 应更多: short=%d long=%d", short, long)
	}
	cn := estimateTokens(strings.Repeat("中", 100))
	if cn < 50 {
		t.Errorf("中文 token 估算偏低: %d", cn)
	}
}

// ---- mock 剧本 ----

func TestVulnPathAllScripts(t *testing.T) {
	for _, s := range mockScripts {
		p := vulnPath(s)
		if p == "" {
			t.Errorf("剧本 %s 缺探测路径", s.Name)
		}
	}
}

func TestScriptIntentsIncludeWebCheck(t *testing.T) {
	s := pickScript("example.com")
	intents := scriptIntents(s, "example.com")
	if len(intents) != 4 {
		t.Fatalf("应 4 条意图, got %d", len(intents))
	}
	joined := ""
	for _, i := range intents {
		if i["title"] == nil || i["description"] == nil {
			t.Errorf("意图缺字段: %+v", i)
		}
		joined += i["title"].(string)
	}
	if !strings.Contains(joined, "example.com") {
		t.Errorf("意图标题应含目标: %s", joined)
	}
}

// ---- mock worker 剧本分发 ----

func TestWorkStratumBranchSelection(t *testing.T) {
	p := NewMockProvider()
	cases := []struct {
		intentTitle string
		wantTool    string // 第一个工具应是 bash 或 webfetch
	}{
		{"枚举 example.com 的子域名与服务", "bash"},
		{"对 example.com 的服务做端口与版本探测", "bash"},
		{"检查 example.com 的 Web 服务漏洞", "webfetch"},
		{"验证 example.com 的漏洞利用链", "webfetch"},
		{"随便一个未知意图", "bash"},
	}
	for _, c := range cases {
		req := ChatRequest{Messages: []Message{
			{Role: RoleSystem, Content: "你是渗透测试系统的 Worker"},
			{Role: RoleUser, Content: "意图标题: " + c.intentTitle},
		}}
		resp := p.workStratum(req, mockState{Target: "example.com"})
		if len(resp.ToolCalls) != 1 {
			t.Errorf("%q: 应返回 1 个工具调用, got %d", c.intentTitle, len(resp.ToolCalls))
			continue
		}
		got := resp.ToolCalls[0].Function.Name
		if got != c.wantTool {
			t.Errorf("%q: 首工具 %s, 期望 %s", c.intentTitle, got, c.wantTool)
		}
	}
}

func TestWorkStratumWriteProbeGated(t *testing.T) {
	// 默认关闭：不发 POST
	p := NewMockProvider()
	req := ChatRequest{Messages: []Message{
		{Role: RoleSystem, Content: "你是 Worker"},
		{Role: RoleUser, Content: "意图标题: 验证 example.com 的漏洞利用链"},
	}}
	foundPOST := false
	for turn := 0; turn < 6; turn++ {
		resp := p.workStratum(req, mockState{Target: "example.com"})
		if len(resp.ToolCalls) == 0 {
			break
		}
		args, _ := ParseArgs(resp.ToolCalls[0].Function.Arguments)
		if args["method"] == "POST" {
			foundPOST = true
		}
		// 模拟回注，累积轮次
		req.Messages = append(req.Messages,
			Message{Role: RoleAssistant, ToolCalls: resp.ToolCalls},
			Message{Role: RoleTool, ToolCallID: resp.ToolCalls[0].ID, Content: "result: ok"})
	}
	if foundPOST {
		t.Error("默认不应发出 POST 探测")
	}

	// 开启后：应出现 POST
	p2 := NewMockProvider()
	p2.SetAllowWriteProbe(true)
	req2 := ChatRequest{Messages: []Message{
		{Role: RoleSystem, Content: "你是 Worker"},
		{Role: RoleUser, Content: "意图标题: 验证 example.com 的漏洞利用链"},
	}}
	postSeen := false
	for turn := 0; turn < 6; turn++ {
		resp := p2.workStratum(req2, mockState{Target: "example.com"})
		if len(resp.ToolCalls) == 0 {
			break
		}
		args, _ := ParseArgs(resp.ToolCalls[0].Function.Arguments)
		if args["method"] == "POST" {
			postSeen = true
			break
		}
		req2.Messages = append(req2.Messages,
			Message{Role: RoleAssistant, ToolCalls: resp.ToolCalls},
			Message{Role: RoleTool, ToolCallID: resp.ToolCalls[0].ID, Content: "result: ok"})
	}
	if !postSeen {
		t.Error("开启 allowWriteProbe 后应发出 POST 探测")
	}
}

// ---- 工具 schema ----

func TestToolSetRequiredTools(t *testing.T) {
	required := []string{
		"set_goals", "add_task_scope", "set_constraints",
		"add_intent", "prove_goal",
		"insert_assets", "record_fact", "report_finding",
		"bash", "webfetch",
		"search_all_worker_traces", "get_worker_trace",
	}
	for _, name := range required {
		if _, ok := ToolByName(name); !ok {
			t.Errorf("缺少必需工具: %s", name)
		}
	}
}

func TestToolSchemaHasParams(t *testing.T) {
	tl := ToolSchema("x", "desc", map[string]any{"a": Prop("string", "字段")}, []string{"a"})
	if tl.Type != "function" || tl.Function.Name != "x" {
		t.Errorf("schema 结构错: %+v", tl)
	}
	p := tl.Function.Raw.(map[string]any)
	if p["type"] != "object" {
		t.Errorf("应为 object: %v", p["type"])
	}
}

// ---- 消息解析辅助 ----

func TestDetectRole(t *testing.T) {
	planner := detectRole([]Message{{Role: RoleSystem, Content: "You are the Planner of this system"}})
	if planner != "planner" {
		t.Errorf("应识别 planner, got %s", planner)
	}
	worker := detectRole([]Message{{Role: RoleSystem, Content: "You are a Worker executor"}})
	if worker != "worker" {
		t.Errorf("应识别 worker, got %s", worker)
	}
	main := detectRole([]Message{{Role: RoleSystem, Content: "You are the entry Agent"}})
	if main != "main" {
		t.Errorf("应识别 main, got %s", main)
	}
}

func TestFirstHostInMessages(t *testing.T) {
	got := firstHostInMessages([]Message{
		{Role: RoleUser, Content: "请探测 example.com 的资产"},
	})
	if got != "example.com" {
		t.Errorf("应提取 example.com, got %q", got)
	}
	if firstHostInMessages([]Message{{Role: RoleUser, Content: "没有域名"}}) != "" {
		t.Error("无域名时应返回空")
	}
}