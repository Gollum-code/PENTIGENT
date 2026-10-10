package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"time"
)

const workerSystemPrompt = `你是渗透测试系统的 Worker（执行者）。
你领到一条 intent（意图）。你的职责：
1) 用真实工具（bash / webfetch）执行探测；
2) 用 insert_assets 提交发现的资产（父子关系/去重由系统程序计算）；
3) 用 record_fact 写探测结论（事实节点）；
4) 用 report_finding 报告漏洞（含 severity + evidence）；
5) 可 search_all_worker_traces / get_worker_trace 参考其他 worker 的执行过程。
执行完即停止（一个意图一个回合），不要继续越权动作。危险操作会过审批门。`

type Worker struct {
	Store Store
	Guard Guard
	// CompanyID 该任务绑定的公司（资产归属），从 task 查出后注入，禁止硬编码
	CompanyID int64
}

// WorkerResult 一次意图执行的产出
type WorkerResult struct {
	IntentID    int64
	NewFacts    int
	NewFindings int
	NewAssets   int
	Steps       int
	InputTokens int
	OutputTokens int
	Status      string // done | blocked | error
	Error       string
}

// Run 领一条意图并执行，直到 LLM 不再调用工具或到 maxRounds
func (w *Worker) Run(ctx context.Context, taskID, explorationID int64, intent *Node, maxRounds int) WorkerResult {
	res := WorkerResult{IntentID: intent.ID, Status: "done"}

	if maxRounds <= 0 {
		maxRounds = 12
	}

	// 工具集（worker 侧可用）
	var tools []Tool
	for _, name := range []string{"bash", "webfetch", "insert_assets", "record_fact", "report_finding",
		"search_all_worker_traces", "get_worker_trace"} {
		if t, ok := ToolByName(name); ok {
			tools = append(tools, t)
		}
	}

	intentDesc := ""
	if d, ok := intent.Content["description"].(string); ok {
		intentDesc = d
	}

	messages := []Message{
		{Role: RoleSystem, Content: workerSystemPrompt},
		{Role: RoleUser, Content: fmt.Sprintf("任务ID: %d\n意图ID: %d\n意图标题: %s\n意图描述: %s\n\n请执行该意图并用工具写回结果。",
			taskID, intent.ID, intent.Title, intentDesc)},
	}

	for round := 0; round < maxRounds; round++ {
		resp, err := CurrentProvider().Chat(ctx, ChatRequest{
			Messages:    messages,
			Tools:       tools,
			MaxTokens:   2048,
			Temperature: 0.2,
		})
		if err != nil {
			res.Status = "error"
			res.Error = err.Error()
			log.Printf("worker %d: llm error: %v", intent.ID, err)
			return res
		}
		res.InputTokens += resp.Usage.InputTokens
		res.OutputTokens += resp.Usage.OutputTokens

		// 记录 planner/worker 本轮 LLM 调用到 activity
		w.logLLMActivity(ctx, taskID, explorationID, intent.ID, resp)

		if len(resp.ToolCalls) == 0 {
			break // LLM 停止调用工具 → 意图完成
		}

		// 组装 assistant 消息（带 tool_calls）
		assistantMsg := Message{Role: RoleAssistant, Content: resp.Content, ToolCalls: resp.ToolCalls}
		messages = append(messages, assistantMsg)

		// 逐个执行工具
		for _, call := range resp.ToolCalls {
			res.Steps++
			resultText := w.executeTool(ctx, taskID, explorationID, intent.ID, call, &res)
			// 回注 tool result
			messages = append(messages, Message{
				Role:       RoleTool,
				ToolCallID: call.ID,
				Content:    resultText,
			})
		}
		time.Sleep(100 * time.Millisecond) // 防止 mock 自循环太快
	}

	return res
}

func (w *Worker) logLLMActivity(ctx context.Context, taskID, explorationID, nodeID int64, resp ChatResponse) {
	// 尝试从 DB 记录 token 消耗（失败不致命）
	if w.Store == nil {
		return
	}
	_, _ = w.Store.LogActivity(ctx, Activity{
		TaskID:        &taskID,
		ExplorationID: &explorationID,
		NodeID:        &nodeID,
		Role:          "worker",
		Step:          "llm_turn",
		Status:        "ok",
		InputTokens:   resp.Usage.InputTokens,
		OutputTokens:  resp.Usage.OutputTokens,
	})
}

// executeTool 执行单个工具调用，返回 tool result 文本
func (w *Worker) executeTool(ctx context.Context, taskID, explorationID, nodeID int64, call ToolCall, res *WorkerResult) string {
	args, err := ParseArgs(call.Function.Arguments)
	if err != nil {
		w.logTool(ctx, taskID, explorationID, nodeID, call.Function.Name, args, "error", err.Error())
		return fmt.Sprintf("result(%s): 参数解析失败: %v", call.Function.Name, err)
	}

	// 审批门
	var decision Decision
	if w.Guard != nil {
		decision, err = w.Guard.Check(call.Function.Name, args)
		if err != nil {
			w.logTool(ctx, taskID, explorationID, nodeID, call.Function.Name, args, "error", err.Error())
			return fmt.Sprintf("result(%s): 审批门异常: %v", call.Function.Name, err)
		}
	} else {
		decision = Decision{Action: "allow"}
	}

	switch decision.Action {
	case "deny":
		w.logTool(ctx, taskID, explorationID, nodeID, call.Function.Name, args, "denied", decision.Reason)
		return fmt.Sprintf("result(%s): 被审批门拒绝: %s", call.Function.Name, decision.Reason)

	case "ask":
		// 进待审批队列，然后轮询等待人工裁决（有界等待，人不批就 timeout）
		pid, err := w.Store.EnqueueIntercept(ctx, PendingIntercept{
			TaskID: &taskID,
			NodeID: &nodeID,
			Tool:   call.Function.Name,
			Input:  args,
			Reason: decision.Reason,
		})
		if err != nil {
			w.logTool(ctx, taskID, explorationID, nodeID, call.Function.Name, args, "error", err.Error())
			return fmt.Sprintf("result(%s): 入队失败 %v", call.Function.Name, err)
		}
		w.logTool(ctx, taskID, explorationID, nodeID, call.Function.Name, args, "waiting", decision.Reason)
		verdict := w.waitApproval(ctx, pid)
		switch verdict {
		case "approved":
			// 人工放行 → 继续执行（沿用常规执行路径）
			log.Printf("worker: pending %d 已人工放行，继续执行 %s", pid, call.Function.Name)
			return w.executeAllowed(ctx, taskID, explorationID, nodeID, call, args, res)
		case "denied":
			w.logTool(ctx, taskID, explorationID, nodeID, call.Function.Name, args, "denied", "人工审批拒绝")
			return fmt.Sprintf("result(%s): 人工审批拒绝", call.Function.Name)
		default:
			// 超时：任务被上下文取消 → 上报；否则标记等待中，让 LLM 决定
			w.logTool(ctx, taskID, explorationID, nodeID, call.Function.Name, args, "waiting", "审批超时，稍后重试")
			return fmt.Sprintf("result(%s): 已提交人工审批（pending id=%d），审批超时，请稍后再试或换方案", call.Function.Name, pid)
		}

	case "allow":
		return w.executeAllowed(ctx, taskID, explorationID, nodeID, call, args, res)
	}
	return fmt.Sprintf("result(%s): 未知动作", call.Function.Name)
}

// waitApproval 轮询等待人工裁决。返回 approved / denied / timeout。
func (w *Worker) waitApproval(ctx context.Context, pendingID int64) string {
	const maxWait = 120 * time.Second
	const poll = 2 * time.Second
	deadline := time.Now().Add(maxWait)
	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return "timeout"
		case <-time.After(poll):
		}
		status, err := w.Store.GetPendingStatus(ctx, pendingID)
		if err != nil {
			continue
		}
		switch status {
		case "approved":
			return "approved"
		case "denied":
			return "denied"
		}
	}
	return "timeout"
}

// executeAllowed 执行已过审批的工具调用（ask 人工放行后也走这里）
func (w *Worker) executeAllowed(ctx context.Context, taskID, explorationID, nodeID int64, call ToolCall, args map[string]any, res *WorkerResult) string {
	switch call.Function.Name {
	case "bash", "webfetch":
		out, err := ExecNative(ctx, call.Function.Name, args)
		status := "ok"
		if err != nil {
			status = "error"
		}
		w.logTool(ctx, taskID, explorationID, nodeID, call.Function.Name, args, status, out)
		return fmt.Sprintf("result(%s): %s", call.Function.Name, out)

	case "insert_assets":
		return w.handleInsertAssets(ctx, taskID, explorationID, nodeID, args, res)

	case "record_fact":
		return w.handleRecordFact(ctx, taskID, explorationID, nodeID, args, res)

	case "report_finding":
		return w.handleReportFinding(ctx, taskID, explorationID, nodeID, args, res)

	case "search_all_worker_traces":
		q, _ := args["query"].(string)
		rows, err := w.Store.SearchWorkerTraces(ctx, taskID, q, 10)
		if err != nil {
			return fmt.Sprintf("result(search): %v", err)
		}
		items := make([]map[string]any, 0, len(rows))
		for _, r := range rows {
			items = append(items, map[string]any{
				"step": r.Step, "tool": r.Tool, "output": r.Output, "status": r.Status,
			})
		}
		b, _ := json.Marshal(items)
		return fmt.Sprintf("result(search_all_worker_traces): %s", string(b))

	case "get_worker_trace":
		var intentID int64
		if f, ok := args["intent_id"].(float64); ok {
			intentID = int64(f)
		}
		rows, err := w.Store.GetWorkerTrace(ctx, intentID, 200)
		if err != nil {
			return fmt.Sprintf("result(get_trace): %v", err)
		}
		b, _ := json.Marshal(rows)
		return fmt.Sprintf("result(get_worker_trace): %s", string(b))
	}
	return fmt.Sprintf("result(%s): 未知动作", call.Function.Name)
}

func (w *Worker) handleInsertAssets(ctx context.Context, taskID, explorationID, nodeID int64, args map[string]any, res *WorkerResult) string {
	rawAssets, _ := args["assets"].([]any)
	if len(rawAssets) == 0 {
		return "result(insert_assets): 空资产列表"
	}
	var lines []string
	statusAll := "ok"
	for _, ra := range rawAssets {
		am, _ := ra.(map[string]any)
		a := Asset{
			Type:       str(am, "type"),
			Domain:     str(am, "domain"),
			RecordType: str(am, "record_type"),
			IP:         str(am, "ip"),
			URL:        str(am, "url"),
			Method:     str(am, "method"),
			Title:      str(am, "title"),
			AppName:    str(am, "app_name"),
		}
		// 资产归属公司：从任务查出的真实 company_id（MVP：未绑定则跳过入库）
		companyID := w.CompanyID
		if companyID <= 0 {
			lines = append(lines, fmt.Sprintf("asset(%s) 跳过：任务未绑定公司", a.Type))
			statusAll = "error"
			continue
		}
		assetID, inserted, err := w.Store.InsertAsset(ctx, companyID, a)
		if err != nil {
			lines = append(lines, fmt.Sprintf("asset(%s) 入库失败: %v", a.Type, err))
			statusAll = "error"
			continue
		}
		if inserted {
			res.NewAssets++
		}
		// 锚点：探索节点 ↔ 资产
		_ = w.Store.Anchor(ctx, explorationID, nodeID, assetID)
		lines = append(lines, fmt.Sprintf("asset(id=%d, type=%s) %s", assetID, a.Type, a.Domain))
	}
	// 转为一行 JSON 便于 LLM 解析
	bs, _ := json.Marshal(lines)
	w.logTool(ctx, taskID, explorationID, nodeID, "insert_assets", args, statusAll, string(bs))
	return fmt.Sprintf("result(insert_assets): %s", string(bs))
}

func (w *Worker) handleRecordFact(ctx context.Context, taskID, explorationID, nodeID int64, args map[string]any, res *WorkerResult) string {
	summary, _ := args["summary"].(string)
	if summary == "" {
		return "result(record_fact): 缺少 summary"
	}
	status := "confirmed"
	if c, ok := args["certainty"].(string); ok && c == "dismissed" {
		status = "dismissed"
	}
	// 写 fact 节点
	factID, err := w.Store.CreateFact(ctx, explorationID, summary, status, args)
	if err != nil {
		return fmt.Sprintf("result(record_fact): %v", err)
	}
	res.NewFacts++
	// 边：intent -> yields -> fact
	_ = w.Store.AddEdge(ctx, explorationID, nodeID, factID, "yields")
	bs, _ := json.Marshal(map[string]any{"fact_id": factID, "status": status})
	w.logTool(ctx, taskID, explorationID, nodeID, "record_fact", args, "ok", string(bs))
	return fmt.Sprintf("result(record_fact): 事实已记录 id=%d", factID)
}

func (w *Worker) handleReportFinding(ctx context.Context, taskID, explorationID, nodeID int64, args map[string]any, res *WorkerResult) string {
	title, _ := args["title"].(string)
	severity, _ := args["severity"].(string)
	if title == "" {
		return "result(report_finding): 缺少 title"
	}
	if severity == "" {
		severity = "info"
	}
	evidence, _ := args["evidence"].(map[string]any)
	// 写 finding 节点
	fid, err := w.Store.CreateFindingNode(ctx, explorationID, title, severity, evidence)
	if err != nil {
		return fmt.Sprintf("result(report_finding): %v", err)
	}
	// 同时写 findings 表
	_, _, _ = w.Store.ReportFinding(ctx, Finding{
		TaskID: &taskID, ExplorationID: &explorationID, NodeID: &fid, Title: title, Severity: severity, Status: "confirmed", Evidence: evidence,
	})
	res.NewFindings++
	_ = w.Store.AddEdge(ctx, explorationID, nodeID, fid, "yields")
	bs, _ := json.Marshal(map[string]any{"finding_id": fid, "severity": severity})
	w.logTool(ctx, taskID, explorationID, nodeID, "report_finding", args, "ok", string(bs))
	return fmt.Sprintf("result(report_finding): 漏洞已报告 id=%d severity=%s", fid, severity)
}

// logTool 工具调用全程留痕
func (w *Worker) logTool(ctx context.Context, taskID, explorationID, nodeID int64, tool string, input map[string]any, status, output string) {
	if w.Store == nil {
		return
	}
	inJSON := map[string]any{}
	for k, v := range input {
		inJSON[k] = v
	}
	outJSON := map[string]any{"text": output}
	_, _ = w.Store.LogActivity(ctx, Activity{
		TaskID:        &taskID,
		ExplorationID: &explorationID,
		NodeID:        &nodeID,
		Role:          "worker",
		Step:          "tool_call",
		Tool:          tool,
		Input:         inJSON,
		Output:        outJSON,
		Status:        status,
	})
}

func str(m map[string]any, k string) string {
	if v, ok := m[k].(string); ok {
		return v
	}
	return ""
}