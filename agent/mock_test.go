package agent

import (
	"context"
	"strings"
	"testing"
)

func TestMockGoalsStratum(t *testing.T) {
	p := NewMockProvider()
	req := ChatRequest{
		Messages: []Message{
			{Role: RoleSystem, Content: "你是渗透测试系统的入口 Agent（Main）"},
			{Role: RoleUser, Content: "任务目标：探测 example.com；授权范围 example.com"},
		},
	}
	resp, err := p.Chat(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.ToolCalls) < 3 {
		t.Fatalf("goals 层应返回 set_goals/add_task_scope/set_constraints，got %d calls", len(resp.ToolCalls))
	}
	names := map[string]bool{}
	for _, c := range resp.ToolCalls {
		names[c.Function.Name] = true
	}
	for _, want := range []string{"set_goals", "add_task_scope", "set_constraints"} {
		if !names[want] {
			t.Errorf("缺少工具调用 %s", want)
		}
	}
}

func TestMockPlannerProgression(t *testing.T) {
	p := NewMockProvider()
	// done=1 时：剩余 3 条独立 intent 一次批量派发（支持 N worker 并发）
	st := mockState{Target: "example.com", DoneIntents: 1}
	resp := p.planStratum(ChatRequest{}, st)
	if len(resp.ToolCalls) != 3 {
		t.Errorf("done=1 时应批量派剩余 3 条 add_intent，got %d calls", len(resp.ToolCalls))
	}
	for _, c := range resp.ToolCalls {
		if c.Function.Name != "add_intent" {
			t.Errorf("批量派发应全是 add_intent，got %s", c.Function.Name)
		}
	}
	// 首次唤醒：4 条全派（无 done 时）
	st0 := mockState{Target: "example.com", DoneIntents: 0}
	resp0 := p.planStratum(ChatRequest{}, st0)
	if len(resp0.ToolCalls) != 4 {
		t.Errorf("done=0 应一次派 4 条，got %d", len(resp0.ToolCalls))
	}
	// 全 done 后 prove_goal
	st2 := mockState{Target: "example.com", DoneIntents: 5}
	resp2 := p.planStratum(ChatRequest{}, st2)
	if len(resp2.ToolCalls) != 1 || resp2.ToolCalls[0].Function.Name != "prove_goal" {
		t.Errorf("done=5 时应证明目标，got %+v", resp2.ToolCalls)
	}
	// 有待办时等待（不派新）
	st3 := mockState{Target: "example.com", OpenIntents: 2}
	resp3 := p.planStratum(ChatRequest{}, st3)
	if len(resp3.ToolCalls) != 0 {
		t.Errorf("有 open intent 时应等待不派发，got %d calls", len(resp3.ToolCalls))
	}
}

func TestExtractIntentChinese(t *testing.T) {
	msgs := []Message{
		{Role: RoleSystem, Content: "你是渗透测试系统的 Worker"},
		{Role: RoleUser, Content: "任务ID: 1\n意图ID: 3\n意图标题: 枚举 example.com 的子域名与服务\n意图描述: 通过 DNS 和 HTTP 指纹确定资产面"},
	}
	got := extractIntent(msgs)
	if !strings.Contains(got, "枚举") || !strings.Contains(got, "example.com") {
		t.Errorf("应提取出中文意图标题，got %q", got)
	}
}

func TestToolSchema(t *testing.T) {
	tools := ToolSet()
	if len(tools) < 12 {
		t.Errorf("工具集应 ≥12 个，got %d", len(tools))
	}
	if _, ok := ToolByName("bash"); !ok {
		t.Error("缺少 bash 工具")
	}
	if _, ok := ToolByName("prove_goal"); !ok {
		t.Error("缺少 prove_goal 工具")
	}
}

func TestMockPing(t *testing.T) {
	p := NewMockProvider()
	info, err := p.Ping(context.Background())
	if err != nil {
		t.Fatalf("mock ping should succeed: %v", err)
	}
	if info == "" {
		t.Error("mock ping info empty")
	}
}

func TestPickScriptDiversity(t *testing.T) {
	// 不同目标应命中不同剧本（多样）；同目标稳定可复现
	seen := map[string]bool{}
	for _, host := range []string{"example.com", "target-a.com", "target-b.net", "lab.local", "demo.org"} {
		seen[pickScript(host).Name] = true
	}
	if len(seen) < 2 {
		t.Errorf("不同目标应产生至少 2 种剧本，got %d (%v)", len(seen), seen)
	}
	// 同目标稳定
	if pickScript("example.com").Name != pickScript("example.com").Name {
		t.Error("同目标应稳定选择同一剧本")
	}
	// 剧本都有漏洞信息
	for _, s := range mockScripts {
		if s.VulnTitle == "" || s.VulnSeverity == "" {
			t.Errorf("剧本 %s 缺漏洞信息", s.Name)
		}
		if len(scriptIntents(s, "example.com")) != 4 {
			t.Errorf("剧本 %s 应产生 4 条意图", s.Name)
		}
	}
}
