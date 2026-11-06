package server

import (
	"net"
	"net/http"
	"sync"
	"time"
)

// rateLimiter 简单的固定窗口限流（进程内，按 key 计数）。
// 用于登录暴力破解防护和免鉴权 LLM 探测的滥用防护。
type rateLimiter struct {
	mu     sync.Mutex
	limit  int
	window time.Duration
	hits   map[string]*rlEntry
}

type rlEntry struct {
	start time.Time
	count int
}

func newRateLimiter(limit int, window time.Duration) *rateLimiter {
	return &rateLimiter{limit: limit, window: window, hits: map[string]*rlEntry{}}
}

// allow 返回是否放行，以及被限流时建议的重试等待时间。
func (l *rateLimiter) allow(key string) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()

	// 机会式清理，避免 map 随 IP 数无限增长
	if len(l.hits) > 2048 {
		for k, v := range l.hits {
			if now.Sub(v.start) > l.window {
				delete(l.hits, k)
			}
		}
	}

	e := l.hits[key]
	if e == nil || now.Sub(e.start) > l.window {
		l.hits[key] = &rlEntry{start: now, count: 1}
		return true, 0
	}
	if e.count >= l.limit {
		return false, l.window - now.Sub(e.start)
	}
	e.count++
	return true, 0
}

// clientIP 取直连 IP；反向代理场景请由前置代理设置/传递真实 IP。
func clientIP(r *http.Request) string {
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}

// isSecureRequest 判断请求是否经 HTTPS（含反向代理终止 TLS 的情况）。
func isSecureRequest(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	return r.Header.Get("X-Forwarded-Proto") == "https"
}
