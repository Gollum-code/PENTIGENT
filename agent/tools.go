package agent

// ToolSet 定义 LLM 可调用的全部工具 schema
func ToolSet() []Tool {
	var tools []Tool

	tools = append(tools, ToolSchema("set_goals", "提交分解后的目标节点",
		map[string]any{"goals": map[string]any{
			"type": "array",
			"items": map[string]any{"type": "object", "properties": map[string]any{
				"title":       Prop("string", "目标标题"),
				"description": Prop("string", "目标描述"),
			}},
		}}, []string{"goals"}))

	tools = append(tools, ToolSchema("add_task_scope", "登记任务授权边界（目标资产范围，硬边界依据）",
		map[string]any{
			"scope": map[string]any{"type": "array", "items": Prop("string", "域名/IP/URL 前缀")},
			"kind":  Prop("string", "scope 类型：domain | ip | url_prefix"),
		}, []string{"scope", "kind"}))

	tools = append(tools, ToolSchema("set_constraints", "登记操作员 allow/deny 约束",
		map[string]any{
			"deny":  map[string]any{"type": "array", "items": Prop("string", "禁止的命令/词")},
			"allow": map[string]any{"type": "array", "items": Prop("string", "允许的命令/词")},
		}, []string{}))

	tools = append(tools, ToolSchema("add_intent", "规划者：派一条可执行意图进 frontier（唯一生成入口）",
		map[string]any{
			"title":       Prop("string", "意图标题"),
			"description": Prop("string", "意图详细描述"),
		}, []string{"title", "description"}))

	tools = append(tools, ToolSchema("prove_goal", "规划者：声明目标已达成",
		map[string]any{
			"goal_ids": map[string]any{"type": "array", "items": map[string]any{"type": "number"}},
			"summary":  Prop("string", "达成摘要"),
		}, []string{"summary"}))

	tools = append(tools, ToolSchema("insert_assets", "worker：提交发现的资产（父子/去重由程序计算）",
		map[string]any{"assets": map[string]any{
			"type":  "array",
			"items": map[string]any{"type": "object", "properties": map[string]any{
				"type":        Prop("string", "root_domain|subdomain|ip|service|endpoint|app"),
				"domain":      Prop("string", "域名"),
				"record_type": Prop("string", "DNS 记录类型 A/CNAME/MX..."),
				"ip":          Prop("string", "IP"),
				"url":         Prop("string", "URL"),
				"method":      Prop("string", "HTTP 方法"),
				"title":       Prop("string", "标题/指纹"),
				"app_name":    Prop("string", "应用名"),
			}, "required": []string{"type"}},
		}}, []string{"assets"}))

	tools = append(tools, ToolSchema("record_fact", "worker：写事实节点（探测结论）",
		map[string]any{
			"summary":     Prop("string", "事实摘要"),
			"asset_id":    map[string]any{"type": "number"},
			"certainty":   Prop("string", "confirmed|dismissed"),
		}, []string{"summary"}))

	tools = append(tools, ToolSchema("report_finding", "worker：报告漏洞",
		map[string]any{
			"title":    Prop("string", "漏洞标题"),
			"severity": map[string]any{"type": "string", "enum": []any{"info", "low", "medium", "high", "critical"}},
			"evidence": map[string]any{"type": "object", "description": "证据详情"},
		}, []string{"title", "severity"}))

	tools = append(tools, ToolSchema("bash", "worker：执行 shell 命令（读操作优先，危险命令过审批门）",
		map[string]any{"command": Prop("string", "要执行的命令")}, []string{"command"}))

	tools = append(tools, ToolSchema("webfetch", "worker：发起 HTTP 请求并留痕",
		map[string]any{"url": Prop("string", "请求 URL")}, []string{"url"}))

	tools = append(tools, ToolSchema("search_all_worker_traces", "worker：搜索其他 worker 的执行过程",
		map[string]any{"query": Prop("string", "搜索关键字")}, []string{"query"}))

	tools = append(tools, ToolSchema("get_worker_trace", "worker：取某个意图的完整执行步骤",
		map[string]any{"intent_id": map[string]any{"type": "number"}}, []string{"intent_id"}))

	return tools
}

// ToolByName 查工具名是否存在
func ToolByName(name string) (Tool, bool) {
	for _, t := range ToolSet() {
		if t.Function.Name == name {
			return t, true
		}
	}
	return Tool{}, false
}