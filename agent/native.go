package agent

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os/exec"
	"runtime"
	"strings"
	"sync/atomic"
	"time"
	"unicode/utf8"
)

func isWindows() bool { return runtime.GOOS == "windows" }

// ExecNative 执行真实工具：bash / webfetch。
// redirectCheck 在 webfetch 每次重定向时调用，用于重新校验目标是否仍在授权范围内
// （否则一个已授权 URL 可 302 到任意域，绕过 guard 的硬边界）。
func ExecNative(ctx context.Context, tool string, args map[string]any, redirectCheck func(url string) error) (string, error) {
	switch tool {
	case "bash":
		cmd, _ := args["command"].(string)
		return runBash(ctx, cmd)
	case "webfetch":
		url, _ := args["url"].(string)
		method, _ := args["method"].(string)
		return runWebfetch(ctx, url, method, redirectCheck)
	}
	return "", fmt.Errorf("未知工具 %q", tool)
}

// bashTimeout 单次 bash 执行超时（可由 config.tools.bash_timeout_sec 覆盖）。
var bashTimeoutNanos atomic.Int64

func init() { bashTimeoutNanos.Store(int64(30 * time.Second)) }

// SetBashTimeoutSeconds 设置 bash 超时；n<=0 保持默认。
func SetBashTimeoutSeconds(n int) {
	if n > 0 {
		bashTimeoutNanos.Store(int64(n) * int64(time.Second))
	}
}

func bashTimeout() time.Duration {
	d := time.Duration(bashTimeoutNanos.Load())
	if d <= 0 {
		return 30 * time.Second
	}
	return d
}

// truncateUTF8 按 rune 边界截断，避免把多字节字符切断产生非法 UTF-8。
func truncateUTF8(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}

func runBash(ctx context.Context, command string) (string, error) {
	if strings.TrimSpace(command) == "" {
		return "", fmt.Errorf("空命令")
	}
	// 超时保护
	cctx, cancel := context.WithTimeout(ctx, bashTimeout())
	defer cancel()

	var cmd *exec.Cmd
	// Windows 下优先用 powershell 兼容更多命令
	if isWindows() {
		cmd = exec.CommandContext(cctx, "powershell", "-NoProfile", "-NonInteractive", "-Command", command)
	} else {
		cmd = exec.CommandContext(cctx, "bash", "-c", command)
	}
	out, err := cmd.CombinedOutput()
	s := strings.TrimSpace(string(out))
	if len(s) > 8192 {
		s = truncateUTF8(s, 8192) + "\n...[truncated]"
	}
	if err != nil {
		return s, fmt.Errorf("bash exit: %w (output: %s)", err, s)
	}
	if s == "" {
		s = "(无输出)"
	}
	return s, nil
}

// userAgent 探测请求的 User-Agent。默认暴露工具身份（透明、可审计）。
// 可通过 SetUserAgent 覆盖为目标站点更可能接受的 UA。
var userAgent atomic.Value // string

func init() { userAgent.Store("pentigent-pentest/1.0") }

// SetUserAgent 覆盖默认 UA（传空字符串恢复默认）
func SetUserAgent(ua string) {
	if ua == "" {
		ua = "pentigent-pentest/1.0"
	}
	userAgent.Store(ua)
}

func currentUserAgent() string {
	if v, ok := userAgent.Load().(string); ok && v != "" {
		return v
	}
	return "pentigent-pentest/1.0"
}

func runWebfetch(ctx context.Context, url, method string, redirectCheck func(string) error) (string, error) {
	if url == "" {
		return "", fmt.Errorf("空 url")
	}
	if method == "" {
		method = http.MethodGet
	}
	method = strings.ToUpper(method)
	cctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()

	var payload io.Reader
	if method == http.MethodPost {
		payload = strings.NewReader(`{"probe":true}`)
	}
	req, err := http.NewRequestWithContext(cctx, method, url, payload)
	if err != nil {
		return "", err
	}
	if method == http.MethodPost {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("User-Agent", currentUserAgent())
	client := &http.Client{
		Timeout: 20 * time.Second,
		CheckRedirect: func(r *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return fmt.Errorf("重定向过多")
			}
			// 重定向目标必须重新过审批门/硬边界，防止用 302 绕出授权范围
			if redirectCheck != nil {
				if err := redirectCheck(r.URL.String()); err != nil {
					return fmt.Errorf("重定向被拦截: %w", err)
				}
			}
			return nil
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
	text := string(body)
	if len(text) > 8192 {
		text = truncateUTF8(text, 8192)
	}
	// 提取 title
	title := extractTitle(text)
	return fmt.Sprintf("HTTP %d\nContent-Type: %s\nTitle: %s\nBody(≤8k):\n%s",
		resp.StatusCode, resp.Header.Get("Content-Type"), title, text), nil
}

func extractTitle(html string) string {
	lower := strings.ToLower(html)
	ti := strings.Index(lower, "<title")
	if ti < 0 {
		return ""
	}
	gt := strings.Index(lower[ti:], ">")
	if gt < 0 {
		return ""
	}
	end := strings.Index(lower[ti+gt:], "</title>")
	if end < 0 {
		return ""
	}
	return strings.TrimSpace(html[ti+gt+1 : ti+gt+end])
}
