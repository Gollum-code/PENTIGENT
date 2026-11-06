package server

import (
	"testing"

	"pentigent/agent"
	"pentigent/db"
)

// LLM 只能重复或收窄操作员给定的授权范围，不能擅自扩大。
func TestFilterLLMScopesRejectsWidening(t *testing.T) {
	anchors := trustedScopeAnchors([]db.ScopeItem{
		{Pattern: "example.com", Kind: "domain"},
		{Pattern: "10.0.0.5", Kind: "ip"},
		{Pattern: "https://api.partner.io/v1", Kind: "url_prefix"},
	}, []string{"extra.example.org"})

	proposed := []agent.ScopeEntry{
		{Pattern: "example.com", Kind: "domain"},                         // 已存在，接受
		{Pattern: "www.example.com", Kind: "domain"},                     // 子域，接受
		{Pattern: "extra.example.org", Kind: "domain"},                   // 描述里推断，接受
		{Pattern: "10.0.0.5", Kind: "ip"},                                // IP 精确，接受
		{Pattern: "https://api.partner.io/v1/users", Kind: "url_prefix"}, // 收窄，接受
		{Pattern: "https://www.example.com/a", Kind: "url_prefix"},       // host 在范围内，接受

		{Pattern: "evil.com", Kind: "domain"},                      // 扩大，拒绝
		{Pattern: "example.com.evil.net", Kind: "domain"},          // 后缀伪装，拒绝
		{Pattern: "10.0.0.6", Kind: "ip"},                          // IP 不在范围，拒绝
		{Pattern: "https://evil.com/v1", Kind: "url_prefix"},       // 其它主机，拒绝
		{Pattern: "https://api.partner.io/v2", Kind: "url_prefix"}, // 超出前缀，拒绝
	}

	accepted, dropped := filterLLMScopes(proposed, anchors)
	gotAccepted := map[string]bool{}
	for _, e := range accepted {
		gotAccepted[e.Pattern] = true
	}
	for _, want := range []string{
		"example.com", "www.example.com", "extra.example.org", "10.0.0.5",
		"https://api.partner.io/v1/users", "https://www.example.com/a",
	} {
		if !gotAccepted[want] {
			t.Errorf("应接受可信范围 %q，实际被丢弃", want)
		}
	}
	for _, e := range accepted {
		switch e.Pattern {
		case "evil.com", "example.com.evil.net", "10.0.0.6",
			"https://evil.com/v1", "https://api.partner.io/v2":
			t.Errorf("越权范围 %q 不应被接受", e.Pattern)
		}
	}
	if len(dropped) != 5 {
		t.Errorf("应丢弃 5 条越权范围，实际 %d 条: %v", len(dropped), dropped)
	}
}

// 没有任何可信锚点时，LLM 提出的任何范围都不能落库。
func TestFilterLLMScopesEmptyAnchorsRejectsAll(t *testing.T) {
	accepted, dropped := filterLLMScopes([]agent.ScopeEntry{
		{Pattern: "example.com", Kind: "domain"},
	}, nil)
	if len(accepted) != 0 || len(dropped) != 1 {
		t.Errorf("无锚点时应全部拒绝，accepted=%v dropped=%v", accepted, dropped)
	}
}

// url_prefix 锚点只授权特定路径，不能放大成整个 host。
func TestURLPrefixAnchorDoesNotWidenToHost(t *testing.T) {
	anchors := []db.ScopeItem{{Pattern: "https://api.partner.io/v1", Kind: "url_prefix"}}
	if scopeEntryTrusted(agent.ScopeEntry{Pattern: "api.partner.io", Kind: "domain"}, anchors) {
		t.Error("url_prefix 锚点不应允许把整个 host 登记为授权范围")
	}
	if !scopeEntryTrusted(agent.ScopeEntry{Pattern: "https://api.partner.io/v1/users", Kind: "url_prefix"}, anchors) {
		t.Error("收窄的 URL 前缀应被接受")
	}
}
