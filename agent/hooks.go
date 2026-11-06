package agent

import "sync"

// findingHook 允许上层（cmd/server）订阅"新漏洞"事件，用于 Webhook/IM 推送。
// 回调在 worker goroutine 内同步调用，实现方应自行异步化，避免阻塞意图执行。
var (
	findingHookMu sync.RWMutex
	findingHook   func(Finding)
)

// SetFindingHook 注册新漏洞回调；传 nil 取消。
func SetFindingHook(fn func(Finding)) {
	findingHookMu.Lock()
	defer findingHookMu.Unlock()
	findingHook = fn
}

func emitFinding(f Finding) {
	findingHookMu.RLock()
	fn := findingHook
	findingHookMu.RUnlock()
	if fn != nil {
		fn(f)
	}
}
