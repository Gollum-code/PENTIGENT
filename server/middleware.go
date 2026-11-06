package server

import (
	"net/http"
	"net/url"
	"strings"
)

// statusRecorder 记录状态码/字节数，并保留 Flusher（SSE 依赖）。
type statusRecorder struct {
	http.ResponseWriter
	status int
	bytes  int
}

func (r *statusRecorder) WriteHeader(code int) {
	if r.status == 0 {
		r.status = code
	}
	r.ResponseWriter.WriteHeader(code)
}

func (r *statusRecorder) Write(b []byte) (int, error) {
	if r.status == 0 {
		r.status = http.StatusOK
	}
	n, err := r.ResponseWriter.Write(b)
	r.bytes += n
	return n, err
}

// Flush 让 SSE 在包装后仍能立即推送。
func (r *statusRecorder) Flush() {
	if f, ok := r.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// sameOriginOK 对状态变更请求做 CSRF 第二道防线：
// 浏览器会带 Origin/Referer，必须与当前 Host 同源；命令行客户端（无 Origin）放行。
// 已使用 Authorization 头的 API 客户端不受 cookie 影响，直接放行。
func sameOriginOK(r *http.Request) bool {
	switch r.Method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return true
	}
	if r.Header.Get("Authorization") != "" {
		return true
	}
	origin := r.Header.Get("Origin")
	if origin == "" {
		origin = r.Header.Get("Referer")
	}
	if origin == "" {
		// 非浏览器客户端（curl/脚本）
		return true
	}
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" {
		return false
	}
	return strings.EqualFold(u.Host, r.Host)
}
