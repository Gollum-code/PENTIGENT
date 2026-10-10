package intercept

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"artex/db"
)

// Guard 审批门：规则匹配 + 资产硬边界
// 决策优先级：intercept_rules(allow/deny/ask) → asset 硬边界(deny) → 默认 allow
type Guard struct {
	store   *db.DB
	rules   []db.InterceptRule
	scope   []db.ScopeItem // 任务授权边界（硬边界分母）
	constraints []struct {
		Kind    string `json:"kind"`
		Pattern string `json:"pattern"`
	}
}

func NewGuard(store *db.DB) *Guard {
	return &Guard{store: store}
}

// Bind 绑定任务上下文：加载任务范围 + 约束（每次任务启动时调用）
func (g *Guard) Bind(ctx context.Context, taskID int64) error {
	rules, err := g.store.ListRules(ctx)
	if err != nil {
		return err
	}
	g.rules = rules

	scope, err := g.store.ListScope(ctx, taskID)
	if err != nil {
		return err
	}
	g.scope = scope

	constraints, err := g.store.ListConstraints(ctx, taskID)
	if err != nil {
		return err
	}
	g.constraints = constraints
	return nil
}

// Decision 决策结果
type Decision struct {
	Action string // allow | deny | ask
	RuleID *int64
	Reason string
}

// Check 对一次工具调用做审批决策
// 决策优先级：deny 规则 → 资产硬边界（bash/webfetch 必检）→ ask 规则 → allow 规则 → 默认 allow
func (g *Guard) Check(ctx context.Context, tool string, input map[string]any) (Decision, error) {
	// 1. deny 规则（先命中先决策，不受 allow 影响）
	for _, r := range g.rules {
		if !r.Enabled || r.Action != "deny" {
			continue
		}
		matched, err := matchRule(r, tool, input)
		if err != nil || !matched {
			continue
		}
		rid := r.ID
		return Decision{Action: "deny", RuleID: &rid, Reason: fmt.Sprintf("规则[%s]拒绝", r.Name)}, nil
	}

	// 2. 资产硬边界：bash/webfetch 必须校验目标在任务范围内（代码硬判，不依赖 LLM/规则）
	if tool == "bash" || tool == "webfetch" {
		targets := extractHosts(tool, input)
		for _, h := range targets {
			if !g.inScope(h) {
				return Decision{Action: "deny", Reason: fmt.Sprintf("资产硬边界：%s 不在任务授权范围内", h)}, nil
			}
		}
	}

	// 2.1 操作员约束（deny 优先于 allow 规则）
	for _, c := range g.constraints {
		if c.Kind == "deny" && strings.Contains(serializeInput(input), c.Pattern) {
			return Decision{Action: "deny", Reason: fmt.Sprintf("操作员约束 deny: %s", c.Pattern)}, nil
		}
	}

	// 3. ask 规则
	for _, r := range g.rules {
		if !r.Enabled || r.Action != "ask" {
			continue
		}
		matched, err := matchRule(r, tool, input)
		if err != nil || !matched {
			continue
		}
		rid := r.ID
		return Decision{Action: "ask", RuleID: &rid, Reason: fmt.Sprintf("规则[%s]要求人工审批", r.Name)}, nil
	}

	// 4. allow 规则
	for _, r := range g.rules {
		if !r.Enabled || r.Action != "allow" {
			continue
		}
		matched, err := matchRule(r, tool, input)
		if err != nil || !matched {
			continue
		}
		rid := r.ID
		return Decision{Action: "allow", RuleID: &rid, Reason: fmt.Sprintf("规则[%s]放行", r.Name)}, nil
	}

	// 5. 默认放行
	return Decision{Action: "allow", Reason: "默认放行"}, nil
}

func matchRule(r db.InterceptRule, tool string, input map[string]any) (bool, error) {
	var target string
	if r.MatchTarget == "tool_name" {
		target = tool
	} else {
		target = serializeInput(input)
	}
	if r.MatchType == "regex" {
		re, err := regexp.Compile(r.Pattern)
		if err != nil {
			return false, err
		}
		return re.MatchString(target), nil
	}
	return strings.Contains(target, r.Pattern), nil
}

func serializeInput(input map[string]any) string {
	b, _ := json.Marshal(input)
	return string(b)
}

// extractHosts 从工具入参中解析出目标 host / URL / IP
func extractHosts(tool string, input map[string]any) []string {
	var raw string
	switch tool {
	case "webfetch":
		u, _ := input["url"].(string)
		if u != "" {
			if parsed, err := url.Parse(u); err == nil && parsed.Host != "" {
				return []string{parsed.Host}
			}
			return []string{u}
		}
	case "bash":
		cmd, _ := input["command"].(string)
		raw = cmd
	}
	if raw == "" {
		return nil
	}
	// 匹配 URL 中的 host
	var out []string
	seen := map[string]bool{}
	urlRe := regexp.MustCompile(`https?://([a-zA-Z0-9\-\.]+(?::\d+)?)`)
	for _, m := range urlRe.FindAllStringSubmatch(raw, -1) {
		if len(m) > 1 && !seen[m[1]] {
			out = append(out, m[1])
			seen[m[1]] = true
		}
	}
	// 匹配裸域名/IP（nslookup/ping/dig/curl 目标）：只取最后一个参数，且必须像域名
	hostRe := regexp.MustCompile(`(?i)(?:nslookup|ping|dig|host)\s+(?:-[^\s]+\s+)*([a-z0-9][a-z0-9\-\.]*\.[a-z]{2,}|[0-9]{1,3}(?:\.[0-9]{1,3}){3})`)
	for _, m := range hostRe.FindAllStringSubmatch(raw, -1) {
		if len(m) > 1 && !seen[m[1]] {
			out = append(out, m[1])
			seen[m[1]] = true
		}
	}
	// 匹配裸 IP（curl/nc 直接给 IP 的场景）
	ipRe := regexp.MustCompile(`(?:curl|nc|netcat|telnet)\s+(?:-[^\s]+\s+)*([0-9]{1,3}(?:\.[0-9]{1,3}){3})`)
	for _, m := range ipRe.FindAllStringSubmatch(raw, -1) {
		if len(m) > 1 && !seen[m[1]] {
			out = append(out, m[1])
			seen[m[1]] = true
		}
	}
	return out
}

// inScope 判断 host 是否在任务授权边界内（后缀匹配 + IP 精确）
func (g *Guard) inScope(host string) bool {
	h := strings.ToLower(strings.TrimSpace(host))
	if h == "" {
		return true // 无目标 → 不拦（如 whoami）
	}
	// 去掉端口
	if i := strings.LastIndex(h, ":"); i > 0 && !strings.Contains(h[i+1:], ".") {
		h = h[:i]
	}
	for _, s := range g.scope {
		p := strings.ToLower(strings.TrimSpace(s.Pattern))
		switch s.Kind {
		case "domain":
			if h == p || strings.HasSuffix(h, "."+p) {
				return true
			}
		case "ip":
			if h == p {
				return true
			}
		case "url_prefix":
			if strings.HasPrefix(h, p) {
				return true
			}
		default:
			if h == p || strings.HasSuffix(h, "."+p) {
				return true
			}
		}
	}
	return false
}