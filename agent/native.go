package agent

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

func isWindows() bool { return runtime.GOOS == "windows" }

// ExecNative 执行真实工具：bash / webfetch
func ExecNative(ctx context.Context, tool string, args map[string]any) (string, error) {
	switch tool {
	case "bash":
		cmd, _ := args["command"].(string)
		return runBash(ctx, cmd)
	case "webfetch":
		url, _ := args["url"].(string)
		method, _ := args["method"].(string)
		return runWebfetch(ctx, url, method)
	}
	return "", fmt.Errorf("未知工具 %q", tool)
}

func runBash(ctx context.Context, command string) (string, error) {
	if strings.TrimSpace(command) == "" {
		return "", fmt.Errorf("空命令")
	}
	// 超时保护
	cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
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
		s = s[:8192] + "\n...[truncated]"
	}
	if err != nil {
		return s, fmt.Errorf("bash exit: %w (output: %s)", err, s)
	}
	if s == "" {
		s = "(无输出)"
	}
	return s, nil
}

func runWebfetch(ctx context.Context, url, method string) (string, error) {
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
	req.Header.Set("User-Agent", "artex-pentest/1.0")
	client := &http.Client{
		Timeout: 20 * time.Second,
		CheckRedirect: func(r *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return fmt.Errorf("重定向过多")
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
		text = text[:8192]
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