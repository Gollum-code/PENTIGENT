package intercept

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"

	"pentigent/db"
)

// Guard 审批门：规则匹配 + 资产硬边界
// 决策优先级：asset 黑名单(deny) → intercept_rules(deny) → asset 硬边界 → 操作员约束 → ask 规则 → allow 规则 → 默认 allow
type Guard struct {
	store       *db.DB
	rules       []db.InterceptRule
	assetRules  []db.AssetRule // 资产黑名单（硬边界，永不探测）
	scope       []db.ScopeItem // 任务授权边界（硬边界分母）
	constraints []operatorConstraint
}

// operatorConstraint 操作员针对单个任务登记的 deny/allow 约束
type operatorConstraint struct {
	Kind    string `json:"kind"`
	Pattern string `json:"pattern"`
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
	for _, c := range constraints {
		g.constraints = append(g.constraints, operatorConstraint{Kind: c.Kind, Pattern: c.Pattern})
	}
	return nil
}

// isExecTool 是否真正对外执行命令/请求的工具。
// 指令类黑名单（命令模式）只对这类工具有意义；纯写图工具（insert_assets /
// record_fact / report_finding / trace 查询）的入参是数据文本，
// 用命令模式去匹配会把"把攻击本身写进漏洞标题/事实"这类合法记录也误拒。
func isExecTool(tool string) bool {
	return tool == "bash" || tool == "webfetch"
}

// normalizeHost 规范化主机：去空白、去括号、去端口；IPv6 统一成压缩形式。
// 例："Example.COM:443" -> "example.com"；"[::1]:8080" -> "::1"；
//
//	"0:0:0:0:0:0:0:1" -> "::1"。
func normalizeHost(h string) string {
	h = strings.ToLower(strings.TrimSpace(h))
	if h == "" {
		return ""
	}
	// URL 中的 IPv6 用方括号包裹，可能还带端口：[::1]:8080
	if strings.HasPrefix(h, "[") {
		if end := strings.IndexByte(h, ']'); end > 0 {
			h = h[1:end]
		}
	}
	if ip := net.ParseIP(h); ip != nil {
		return ip.String()
	}
	// 非方括号 IPv6（含多个冒号）无法与端口可靠区分，保持原样
	if strings.Count(h, ":") >= 2 {
		return h
	}
	// 去掉域名端口
	if i := strings.LastIndex(h, ":"); i > 0 && !strings.Contains(h[i+1:], ".") {
		h = h[:i]
	}
	return h
}

// ScopeAllows 返回 host 是否落在任务授权范围内（资产入库用）。
func (g *Guard) ScopeAllows(host string) bool { return g.inScope(host) }

// hostMatches host 与模式匹配（忽略端口；支持 IP 精确 + 域名后缀）
func hostMatches(host, pattern string) bool {
	host = normalizeHost(host)
	pattern = normalizeHost(pattern)
	if host == "" || pattern == "" {
		return false
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
// 决策优先级：deny 规则 → 资产硬边界（bash/webfetch 必检）→ 约束 deny → 约束 allow
//
//	→ ask 规则 → allow 规则 → 默认 allow
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
		if !r.Enabled || r.Action != "deny" || !ruleAppliesTo(r, tool) {
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
		// curl 跟随重定向时，后续跳转目标无法被 guard 预判 → fail-closed 拒绝
		if tool == "bash" {
			if reason := followRedirectDenied(input); reason != "" {
				return Decision{Action: "deny", Reason: reason}, nil
			}
		}
		targets := extractHosts(tool, input)
		urls := extractURLs(tool, input)
		for _, h := range targets {
			if !g.inScopeTarget(h, urls) {
				return Decision{Action: "deny", Reason: fmt.Sprintf("资产硬边界：%s 不在任务授权范围内", h)}, nil
			}
		}
	}

	// 2.1 操作员约束（deny 优先于 allow 规则）。
	// 约束是命令行模式，只对执行类工具生效：否则漏洞标题/事实里出现 "shutdown"
	// 之类的字样会把正常的记录动作也拦掉。
	if isExecTool(tool) {
		inputStr := serializeInput(input)
		for _, c := range g.constraints {
			if c.Kind == "deny" && c.Pattern != "" && strings.Contains(inputStr, c.Pattern) {
				return Decision{Action: "deny", Reason: fmt.Sprintf("操作员约束 deny: %s", c.Pattern)}, nil
			}
		}
		// 2.2 操作员 allow 约束：命中则跳过 ask（仍受上面的 deny 规则/硬边界约束）
		for _, c := range g.constraints {
			if c.Kind == "allow" && c.Pattern != "" && strings.Contains(inputStr, c.Pattern) {
				return Decision{Action: "allow", Reason: fmt.Sprintf("操作员约束 allow: %s", c.Pattern)}, nil
			}
		}
	}

	// 3. ask 规则
	for _, r := range g.rules {
		if !r.Enabled || r.Action != "ask" || !ruleAppliesTo(r, tool) {
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
		if !r.Enabled || r.Action != "allow" || !ruleAppliesTo(r, tool) {
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
//
// 关键设计：只拦"本地文件访问"，绝不按子串匹配敏感文件名 ——
// 授权目标上的 /.env、/config.json、/credentials 是渗透测试的常规检查点，
// 出现在 URL 路径里的敏感文件名是合法目标，只有本地路径形态才拦。
func selfProbeDenied(tool string, input map[string]any) string {
	switch tool {
	case "webfetch":
		u, _ := input["url"].(string)
		if u == "" {
			return ""
		}
		parsed, err := url.Parse(u)
		if err != nil {
			return ""
		}
		if strings.EqualFold(parsed.Scheme, "file") {
			return "禁止通过 webfetch 读取本地文件（file://）"
		}
		// 说明：本机/回环地址不在这里硬禁 —— 它和其它目标一样由 task_scope 硬边界裁决。
		// 这样既允许"授权范围内的本地靶场（如 DVWA）"，又不会放过未授权的本机探测。
		return ""

	case "bash":
		cmd, _ := input["command"].(string)
		if cmd == "" {
			return ""
		}
		return bashSelfProbeDenied(cmd)
	}
	return ""
}

// 敏感本地文件名（凭据/配置/密钥/版本控制）
var sensitiveLocalNames = []string{
	"config.json", ".env", "id_rsa", "id_ed25519", ".ssh", "credentials",
	"shadow", "known_hosts", ".git-credentials", "apikeys",
	"webui/dist", "logs/", "go.sum", ".git/",
}

// 本地文件系统枚举命令（按"有效命令首 token"判定，避免 mkdir 之类被 "dir " 子串误伤）
var localEnumCommands = map[string]bool{
	"dir": true, "ls": true, "gci": true, "get-childitem": true,
	"pwd": true, "get-location": true, "tree": true,
}

// 会读写本地文件的命令：其参数 token 即使不带路径分隔符也按本地文件处理
// （如 `type config.json`、`cat .env`）
var localFileCommands = map[string]bool{
	"get-content": true, "gc": true, "cat": true, "type": true, "more": true,
	"copy": true, "cp": true, "copy-item": true, "move": true, "mv": true, "move-item": true,
	"remove-item": true, "ri": true, "del": true, "erase": true, "rm": true,
	"get-item": true, "select-string": true, "sls": true, "import-csv": true,
}

// effectiveCommandFields 解析一条命令片段的"有效命令字段"。
// 处理 `powershell -Command "Get-ChildItem ..."` / `cmd /c dir` 这类包装形式。
func effectiveCommandFields(fields []string) []string {
	for i := 0; i < len(fields)-1; i++ {
		switch strings.ToLower(strings.Trim(fields[i], `"'`)) {
		case "powershell", "pwsh", "cmd":
			switch strings.ToLower(fields[i+1]) {
			case "-command", "-c", "/c":
				return fields[i+2:]
			}
		}
	}
	return fields
}

// looksLikeLocalPath token 是否是本地路径形态（绝对路径/相对路径/盘符/环境变量）。
// http(s) URL 一律不算。
func looksLikeLocalPath(tok string) bool {
	t := strings.Trim(tok, `"'`)
	if t == "" {
		return false
	}
	lower := strings.ToLower(t)
	if strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://") {
		return false
	}
	if strings.HasPrefix(t, "/") || strings.HasPrefix(t, `\\`) ||
		strings.HasPrefix(t, "~") || strings.HasPrefix(t, "%") ||
		strings.HasPrefix(lower, "./") || strings.HasPrefix(lower, "../") {
		return true
	}
	// Windows 盘符 X:\ 或 X:/
	if len(t) >= 2 && t[1] == ':' {
		if c := t[0]; (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') {
			return true
		}
	}
	return false
}

// containsSensitiveLocalName 路径里是否包含敏感文件名（返回命中的名字，未命中返回空）
func containsSensitiveLocalName(path string) string {
	// 统一分隔符，让 Windows 反斜杠路径也能命中 logs/、.git/、webui/dist
	lower := strings.ToLower(strings.ReplaceAll(path, `\`, "/"))
	for _, n := range sensitiveLocalNames {
		if strings.Contains(lower, n) {
			return n
		}
	}
	return ""
}

var bashURLRe = regexp.MustCompile(`https?://[^\s"'` + "`" + `]+`)

func bashSelfProbeDenied(cmd string) string {
	// 先剔除 URL 片段：https://target/.env 里的 ".env" 是目标路径，不是本地文件
	stripped := bashURLRe.ReplaceAllString(cmd, " ")

	for _, seg := range strings.FieldsFunc(stripped, func(r rune) bool {
		return r == ';' || r == '|' || r == '&' || r == '\n' || r == '\r'
	}) {
		fields := strings.Fields(seg)
		if len(fields) == 0 {
			continue
		}
		eff := effectiveCommandFields(fields)
		if len(eff) == 0 {
			continue
		}
		cmdName := strings.ToLower(strings.Trim(eff[0], `"'`))

		// 1) 枚举本机文件系统（dir / ls / Get-ChildItem / pwd ...）
		if localEnumCommands[cmdName] {
			return "禁止枚举本机文件系统（与授权目标无关）"
		}

		// 2) 敏感本地文件：路径形态的 token 直接判；本地读写命令的参数按本地文件判
		isLocalFileCmd := localFileCommands[cmdName]
		for _, f := range eff[1:] {
			tok := strings.Trim(f, `"'`)
			if tok == "" {
				continue
			}
			if looksLikeLocalPath(tok) || isLocalFileCmd {
				if n := containsSensitiveLocalName(tok); n != "" {
					return fmt.Sprintf("禁止读取本地敏感路径（%s）", n)
				}
			}
		}
	}
	return ""
}

// followRedirectDenied 拦截 bash 里 curl 跟随重定向的命令。
// 重定向目标无法在 guard 阶段预判，只能 fail-closed；
// 需要跳转检查时改用 webfetch（执行层会逐个重定向重新过 guard）。
func followRedirectDenied(input map[string]any) string {
	cmd, _ := input["command"].(string)
	if cmd == "" || !strings.Contains(strings.ToLower(cmd), "curl") {
		return ""
	}
	// 按命令分隔符切段，只看真正包含 curl 的段，避免把后面的 `ls -l` 误判
	segs := strings.FieldsFunc(cmd, func(r rune) bool {
		return r == ';' || r == '|' || r == '&' || r == '\n'
	})
	for _, seg := range segs {
		if !strings.Contains(strings.ToLower(seg), "curl") {
			continue
		}
		for _, f := range strings.Fields(seg) {
			if f == "--location" || f == "--follow" {
				return "禁止在 bash 中用 curl 跟随重定向（-L/--location）：跳转目标无法校验是否在授权范围内；请改用 webfetch 或手动逐跳检查"
			}
			// 组合短参数如 -sL / -kL
			if strings.HasPrefix(f, "-") && !strings.HasPrefix(f, "--") &&
				strings.Contains(strings.ToLower(f), "l") {
				return "禁止在 bash 中用 curl 跟随重定向（-L/--location）：跳转目标无法校验是否在授权范围内；请改用 webfetch 或手动逐跳检查"
			}
		}
	}
	return ""
}

// ruleAppliesTo 规则是否作用于该工具。
// tool_input 规则匹配的是命令/参数模式，只对执行类工具（bash/webfetch）生效；
// 否则 insert_assets 的 url/method、report_finding 的标题证据这类纯数据文本会被
// 命令黑名单误伤（比如记录一个"允许 rm -rf 的 RCE"漏洞会被拒）。
// tool_name 规则对所有工具生效。
func ruleAppliesTo(r db.InterceptRule, tool string) bool {
	if r.MatchTarget == "tool_input" && !isExecTool(tool) {
		return false
	}
	return true
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
				return []string{normalizeHost(parsed.Host)}
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
		h = normalizeHost(h)
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
	//    域名部分要求含点，避免把 IPv6 的 "fe80" 前缀当成独立主机；
	//    额外支持方括号 IPv6（-Host [::1]）。
	flagRe := regexp.MustCompile(`(?i)(?:--?[a-z\-]*(?:computername|host|server|domain|target|addr|ip|hostname)[a-z\-]*)\s+["']?(\[[0-9a-fA-F:]+\]|[a-z0-9][a-z0-9\-]*\.[a-z0-9\-\.]*(?::\d+)?|[0-9]{1,3}(?:\.[0-9]{1,3}){3})["']?`)
	for _, m := range flagRe.FindAllStringSubmatch(raw, -1) {
		if len(m) > 1 {
			add(m[1])
		}
	}

	// 3) 命令行里出现的裸 IP（fail-closed：任何 IP 都当作探测目标）
	//    注意：IP 在域名规则之前抓取，避免 1.2.3.4 被当成域名后缀。
	ipRe := regexp.MustCompile(`\b([0-9]{1,3}(?:\.[0-9]{1,3}){3})\b`)
	for _, m := range ipRe.FindAllStringSubmatch(raw, -1) {
		if len(m) > 1 {
			add(m[1])
		}
	}

	// 3.5) IPv6 地址（URL 里通常带方括号 http://[::1]:8080/，命令行里也可能裸写）。
	//      先抓候选再用 net.ParseIP 校验，避免把时间戳 12:34:56 之类当成地址。
	ipv6Re := regexp.MustCompile(`\[[0-9a-fA-F:]+\]|(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}`)
	for _, m := range ipv6Re.FindAllString(raw, -1) {
		cand := strings.Trim(m, "[]")
		if ip := net.ParseIP(cand); ip != nil && ip.To4() == nil {
			add(ip.String())
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
	h := normalizeHost(host)
	if h == "" {
		return true // 无目标 → 不拦（如 whoami）
	}
	hIP := net.ParseIP(h)
	for _, s := range g.scope {
		p := normalizeHost(s.Pattern)
		if p == "" || strings.Contains(p, "://") {
			// url_prefix 由 inScopeTarget 按前缀校验，不能当作域名后缀放大
			continue
		}
		switch s.Kind {
		case "ip":
			if h == p || (hIP != nil && net.ParseIP(p) != nil && net.ParseIP(p).Equal(hIP)) {
				return true
			}
		default: // domain / 空（含把 IPv6 误标成 domain 的历史数据）
			if h == p || strings.HasSuffix(h, "."+p) {
				return true
			}
			if hIP != nil && net.ParseIP(p) != nil && net.ParseIP(p).Equal(hIP) {
				return true
			}
		}
	}
	return false
}

// inScopeTarget 判断一次调用里的某个 host 是否在范围内。
// 规则：host 命中 domain/ip 范围，或该调用携带的某个 URL 命中 url_prefix 范围。
func (g *Guard) inScopeTarget(host string, urls []string) bool {
	h := normalizeHost(host)
	if h == "" {
		return true
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
				if uHost := hostOf(lu); uHost == "" || uHost == h {
					return true
				}
			}
		}
	}
	return g.inScope(host)
}

// hostOf 从 URL 提取 host（不含端口；IPv6 规范化）
func hostOf(rawURL string) string {
	if parsed, err := url.Parse(rawURL); err == nil && parsed.Hostname() != "" {
		return normalizeHost(parsed.Hostname())
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
