package intercept

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"pentigent/db"
)

// Guard 审批门：规则匹配 + 资产硬边界
// 决策优先级：asset 黑名单(deny) → intercept_rules(deny) → asset 硬边界 → 操作员约束 → ask 规则 → allow 规则 → 默认 allow
type Guard struct {
	store      *db.DB
	rules      []db.InterceptRule
	assetRules []db.AssetRule // 资产黑名单（硬边界，永不探测）
	scope      []db.ScopeItem // 任务授权边界（硬边界分母）
	constraints []struct {
		Kind    string `json:"kind"`
		Pattern string `json:"pattern"`
	}
}

func NewGuard(store *db.DB) *Guard {
	return &Guard{store: store}
}

// Bind 绑定任务上下文：加载拦截规则 + 资产黑名单 + 任务范围 + 约束（每次任务启动时调用）
func (g *Guard) Bind(ctx context.Context, taskID int64) error {
	rules, err := g.store.ListRules(ctx)
	if err != nil {
		return err
	}
	g.rules = rules

	// 资产黑名单：全局生效，与任务 scope 无关（云元数据等永禁目标）
	assetRules, err := g.store.ListAssetRules(ctx)
	if err != nil {
		return err
	}
	g.assetRules = assetRules

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

// hostMatches host 与模式匹配（忽略端口；支持 IP 精确 + 域名后缀）
func hostMatches(host, pattern string) bool {
	host = strings.ToLower(strings.TrimSpace(host))
	pattern = strings.ToLower(strings.TrimSpace(pattern))
	if host == "" || pattern == "" {
		return false
	}
	// 去掉端口
	if i := strings.LastIndex(host, ":"); i > 0 && !strings.Contains(host[i+1:], ".") {
		host = host[:i]
	}
	return host == pattern || strings.HasSuffix(host, "."+pattern)
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
	// 0. 资产黑名单：永禁目标（云元数据等），最高优先级，与任务 scope 无关
	if tool == "bash" || tool == "webfetch" {
		targets := extractHosts(tool, input)
		for _, h := range targets {
			for _, ar := range g.assetRules {
				if ar.Action != "deny" {
					continue
				}
				if hostMatches(strings.ToLower(h), strings.ToLower(strings.TrimSpace(ar.Pattern))) {
					return Decision{Action: "deny", Reason: fmt.Sprintf("资产黑名单：%s（%s）", h, ar.Note)}, nil
				}
			}
		}
	}

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
		if reason := selfProbeDenied(tool, input); reason != "" {
			return Decision{Action: "deny", Reason: reason}, nil
		}
		targets := extractHosts(tool, input)
		urls := extractURLs(tool, input)
		for _, h := range targets {
			if !g.inScopeTarget(h, urls) {
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

// selfProbeDenied 拦截 agent 对"本机/自身"的探测。
// 真实 LLM 偶尔会把目标搞混，去读本机配置文件或列自身目录 —— 这既无价值又是安全问题。
func selfProbeDenied(tool string, input map[string]any) string {
	raw := ""
	switch tool {
	case "bash":
		raw, _ = input["command"].(string)
	case "webfetch":
		raw, _ = input["url"].(string)
	}
	if raw == "" {
		return ""
	}
	lower := strings.ToLower(raw)

	// 回环地址 / 本机
	for _, needle := range []string{"127.0.0.1", "localhost", "0.0.0.0", "[::1]", ":8080"} {
		if strings.Contains(lower, needle) {
			return fmt.Sprintf("禁止探测本机/自身服务（%s）", needle)
		}
	}
	// 读取本地敏感文件
	for _, needle := range []string{
		"config.json", ".env", "id_rsa", "id_ed25519", ".ssh", "credentials",
		"shadow", "hosts", "known_hosts", ".git-credentials", "apikeys",
		"webui/dist", "logs/", "go.sum", ".git/",
	} {
		if strings.Contains(lower, needle) {
			return fmt.Sprintf("禁止读取本地敏感路径（%s）", needle)
		}
	}
	// 列目录 / 找文件（Get-ChildItem / dir / ls / find）
	for _, needle := range []string{"get-childitem", "get-childitem -recurse", "dir ", "ls -", "get-location", "pwd"} {
		if strings.Contains(lower, needle) {
			return "禁止枚举本机文件系统（与授权目标无关）"
		}
	}
	return ""
}

// matchRule 单条规则的匹配
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
	var out []string
	seen := map[string]bool{}
	add := func(h string) {
		h = strings.TrimSpace(h)
		if h != "" && !seen[h] {
			out = append(out, h)
			seen[h] = true
		}
	}

	// 1) URL 里的 host
	urlRe := regexp.MustCompile(`https?://([a-zA-Z0-9\-\.]+(?::\d+)?)`)
	for _, m := range urlRe.FindAllStringSubmatch(raw, -1) {
		if len(m) > 1 {
			add(m[1])
		}
	}

	// 2) 显式主机参数：-ComputerName / -Host / -Server / -Domain / --host / -target ...
	flagRe := regexp.MustCompile(`(?i)(?:--?[a-z\-]*(?:computername|host|server|domain|target|addr|ip|hostname)[a-z\-]*)\s+["']?([a-z0-9][a-z0-9\-\.]*(?::\d+)?|[0-9]{1,3}(?:\.[0-9]{1,3}){3})["']?`)
	for _, m := range flagRe.FindAllStringSubmatch(raw, -1) {
		if len(m) > 1 {
			add(m[1])
		}
	}

	// 3) 命令行里出现的裸 IP（fail-closed：任何 IP 都当作探测目标）
	ipRe := regexp.MustCompile(`\b([0-9]{1,3}(?:\.[0-9]{1,3}){3})\b`)
	for _, m := range ipRe.FindAllStringSubmatch(raw, -1) {
		if len(m) > 1 {
			add(m[1])
		}
	}

	// 4) 命令行里出现的裸域名（fail-closed：抓所有像域名的 token）
	//    排除常见文件扩展名，避免把 out.txt / config.json 误当目标。
	domainRe := regexp.MustCompile(`\b([a-zA-Z0-9](?:[a-zA-Z0-9\-]*[a-zA-Z0-9])?\.[a-zA-Z]{2,}(?:\.[a-zA-Z]{2,})?)\b`)
	for _, m := range domainRe.FindAllStringSubmatch(raw, -1) {
		if len(m) > 1 && !isFileExt(m[1]) {
			add(m[1])
		}
	}

	return out
}

// isFileExt 判断 token 是否以常见文件扩展名结尾（不是主机名）
func isFileExt(s string) bool {
	i := strings.LastIndex(s, ".")
	if i < 0 {
		return false
	}
	switch strings.ToLower(s[i+1:]) {
	case "txt", "log", "json", "html", "htm", "js", "css", "xml", "png", "jpg",
		"jpeg", "gif", "ico", "php", "py", "go", "md", "csv", "yaml", "yml",
		"conf", "ini", "sh", "bat", "ps1", "db", "sql", "exe", "dll", "bak", "tmp":
		return true
	}
	return false
}

// inScope 判断 host 是否在任务授权边界内（域名后缀 + IP 精确；不含 url_prefix）
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
		default:
			if h == p || strings.HasSuffix(h, "."+p) {
				return true
			}
		}
	}
	return false
}

// inScopeTarget 判断一次调用里的某个 host 是否在范围内。
// 规则：host 命中 domain/ip 范围，或该调用携带的某个 URL 命中 url_prefix 范围。
func (g *Guard) inScopeTarget(host string, urls []string) bool {
	h := strings.ToLower(strings.TrimSpace(host))
	if h == "" {
		return true
	}
	// 去掉端口用于 url_prefix 比较
	hostNoPort := h
	if i := strings.LastIndex(hostNoPort, ":"); i > 0 && !strings.Contains(hostNoPort[i+1:], ".") {
		hostNoPort = hostNoPort[:i]
	}
	for _, s := range g.scope {
		if s.Kind != "url_prefix" {
			continue
		}
		prefix := strings.ToLower(strings.TrimSpace(s.Pattern))
		for _, u := range urls {
			lu := strings.ToLower(u)
			if strings.HasPrefix(lu, prefix) {
				// 该 URL 的 host 必须就是当前校验的 host，避免用 A 的 URL 给 B 放行
				if uHost := hostOf(lu); uHost == "" || uHost == hostNoPort {
					return true
				}
			}
		}
	}
	return g.inScope(host)
}

// hostOf 从 URL 提取 host（不含端口）
func hostOf(rawURL string) string {
	if parsed, err := url.Parse(rawURL); err == nil && parsed.Hostname() != "" {
		return strings.ToLower(parsed.Hostname())
	}
	return ""
}

// extractURLs 从工具入参提取完整 URL（供 url_prefix 校验）
func extractURLs(tool string, input map[string]any) []string {
	var raw string
	switch tool {
	case "webfetch":
		raw, _ = input["url"].(string)
	case "bash":
		raw, _ = input["command"].(string)
	}
	if raw == "" {
		return nil
	}
	urlRe := regexp.MustCompile(`https?://[^\s"'` + "`" + `]+`)
	return urlRe.FindAllString(raw, -1)
}