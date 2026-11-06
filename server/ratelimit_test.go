package server

import (
	"crypto/tls"
	"net/http/httptest"
	"testing"
	"time"
)

func TestRateLimiter(t *testing.T) {
	l := newRateLimiter(2, time.Minute)
	if ok, _ := l.allow("a"); !ok {
		t.Fatal("第 1 次应放行")
	}
	if ok, _ := l.allow("a"); !ok {
		t.Fatal("第 2 次应放行")
	}
	if ok, retry := l.allow("a"); ok {
		t.Fatal("第 3 次应被限流")
	} else if retry <= 0 {
		t.Error("应返回正的重试等待时间")
	}
	// 不同 key 互不影响
	if ok, _ := l.allow("b"); !ok {
		t.Error("不同 key 不应共享计数")
	}
}

func TestIsSecureRequest(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	if isSecureRequest(r) {
		t.Error("普通 HTTP 不应视为安全")
	}
	r.Header.Set("X-Forwarded-Proto", "https")
	if !isSecureRequest(r) {
		t.Error("X-Forwarded-Proto=https 应视为安全")
	}
	r2 := httptest.NewRequest("GET", "/", nil)
	r2.TLS = &tls.ConnectionState{}
	if !isSecureRequest(r2) {
		t.Error("TLS 请求应视为安全")
	}
}

func TestClientIP(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "203.0.113.7:12345"
	if got := clientIP(r); got != "203.0.113.7" {
		t.Errorf("clientIP=%q", got)
	}
}
