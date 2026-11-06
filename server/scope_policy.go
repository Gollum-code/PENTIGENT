package server

import (
	"net"
	"net/url"
	"strings"

	"pentigent/agent"
	"pentigent/db"
)

// 授权范围只能由操作员提供。
//
// goals/planner 都是 LLM，任务描述或目标页面里的内容可能被提示注入，
// 如果直接把 LLM 提出的 add_task_scope 落库，攻击者就能让系统把任意域名
// 写进 task_scope，从而绕过 guard 的资产硬边界（越权探测）。
//
// 因此这里对所有 LLM 提出的范围做"白名单收敛"：
// 只接受落在"可信锚点"内的条目。可信锚点 = 任务创建时操作员登记的范围
// + 从任务目标/描述里抽取出的主机。LLM 无权扩大，只能重复或收窄。

// trustedScopeAnchors 组合可信锚点：操作员已有范围 + 从目标描述推断的主机。
func trustedScopeAnchors(existing []db.ScopeItem, extraHosts []string) []db.ScopeItem {
	out := append([]db.ScopeItem(nil), existing...)
	seen := make(map[string]bool, len(out))
	for _, s := range out {
		seen[strings.ToLower(strings.TrimSpace(s.Pattern))] = true
	}
	for _, h := range extraHosts {
		h = strings.ToLower(strings.TrimSpace(h))
		if h == "" || seen[h] {
			continue
		}
		seen[h] = true
		kind := "domain"
		if net.ParseIP(h) != nil {
			kind = "ip"
		}
		out = append(out, db.ScopeItem{Pattern: h, Kind: kind})
	}
	return out
}

// scopeEntryTrusted 判断 LLM 提出的范围是否被可信锚点覆盖。
func scopeEntryTrusted(entry agent.ScopeEntry, anchors []db.ScopeItem) bool {
	pattern := strings.ToLower(strings.TrimSpace(entry.Pattern))
	if pattern == "" {
		return false
	}
	if entry.Kind == "url_prefix" || strings.Contains(pattern, "://") {
		return urlPrefixTrusted(pattern, anchors)
	}
	host := pattern
	// 允许 LLM 提交 "example.com" 这种带路径的写法，只取 host 部分判断
	if u, err := url.Parse(pattern); err == nil && u.Hostname() != "" {
		host = u.Hostname()
	}
	return hostCoveredByDomainOrIP(host, anchors)
}

// filterLLMScopes 把 LLM 提出的范围分成"接受"和"丢弃"两组（丢弃项用于日志审计）。
func filterLLMScopes(proposed []agent.ScopeEntry, anchors []db.ScopeItem) (accepted []agent.ScopeEntry, dropped []string) {
	for _, e := range proposed {
		if scopeEntryTrusted(e, anchors) {
			accepted = append(accepted, e)
		} else {
			dropped = append(dropped, e.Pattern)
		}
	}
	return accepted, dropped
}

// hostCoveredByDomainOrIP host 是否落在 domain（含子域）/ip 锚点内。
// 注意：url_prefix 锚点不参与这里的判定——它只授权特定路径，不能放大成整个 host。
func hostCoveredByDomainOrIP(host string, anchors []db.ScopeItem) bool {
	host = strings.ToLower(strings.TrimSpace(host))
	host = strings.Trim(host, "[]")
	if host == "" {
		return false
	}
	ip := net.ParseIP(host)
	for _, a := range anchors {
		p := strings.ToLower(strings.TrimSpace(a.Pattern))
		if p == "" {
			continue
		}
		switch a.Kind {
		case "ip":
			if ip != nil && net.ParseIP(p) != nil && net.ParseIP(p).Equal(ip) {
				return true
			}
		default: // domain / 空
			if strings.Contains(p, "://") {
				continue
			}
			if host == p || strings.HasSuffix(host, "."+p) {
				return true
			}
		}
	}
	return false
}

// urlPrefixTrusted 判断一个 URL 前缀是否被已有锚点覆盖：
//  1. 已有 url_prefix 锚点是它的前缀（收窄，接受）；
//  2. 它的 host 落在 domain/ip 锚点内（同一主机下的路径不扩大授权范围）。
func urlPrefixTrusted(prefix string, anchors []db.ScopeItem) bool {
	prefix = strings.ToLower(strings.TrimSpace(prefix))
	u, err := url.Parse(prefix)
	if err != nil || u.Hostname() == "" {
		return false
	}
	for _, a := range anchors {
		if a.Kind != "url_prefix" {
			continue
		}
		ap := strings.ToLower(strings.TrimSpace(a.Pattern))
		if ap != "" && strings.HasPrefix(prefix, ap) {
			return true
		}
	}
	return hostCoveredByDomainOrIP(u.Hostname(), anchors)
}
