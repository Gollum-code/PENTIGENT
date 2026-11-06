package server

import (
	"context"
	"sync"
	"time"

	"pentigent/db"
)

// sseHub 每个任务只启动一个 DB 轮询 goroutine，向所有订阅客户端广播。
// 避免"每个 SSE 客户端一个 ticker"导致的数据库查询放大。
type sseHub struct {
	db       *db.DB
	mu       sync.Mutex
	subs     map[int64]map[chan db.Activity]struct{}
	stops    map[int64]chan struct{}
	interval time.Duration
}

func newSSEHub(database *db.DB) *sseHub {
	return &sseHub{
		db:       database,
		subs:     map[int64]map[chan db.Activity]struct{}{},
		stops:    map[int64]chan struct{}{},
		interval: 700 * time.Millisecond,
	}
}

// subscribe 注册订阅；同一任务的首个订阅者会启动轮询 goroutine，最后一个退订时停止。
func (h *sseHub) subscribe(taskID int64) (<-chan db.Activity, func()) {
	ch := make(chan db.Activity, 256)

	h.mu.Lock()
	if h.subs[taskID] == nil {
		h.subs[taskID] = map[chan db.Activity]struct{}{}
	}
	h.subs[taskID][ch] = struct{}{}
	if h.stops[taskID] == nil {
		stop := make(chan struct{})
		h.stops[taskID] = stop
		go h.poll(taskID, stop)
	}
	h.mu.Unlock()

	var once sync.Once
	unsubscribe := func() {
		once.Do(func() {
			h.mu.Lock()
			defer h.mu.Unlock()
			set := h.subs[taskID]
			if set == nil {
				return
			}
			delete(set, ch)
			if len(set) > 0 {
				return
			}
			delete(h.subs, taskID)
			if stop := h.stops[taskID]; stop != nil {
				close(stop)
				delete(h.stops, taskID)
			}
		})
	}
	return ch, unsubscribe
}

// poll 从"最近 50 条之前"开始，保证订阅瞬间不丢事件；
// 轻微重复由前端按 activity id 去重。
func (h *sseHub) poll(taskID int64, stop <-chan struct{}) {
	ctx := context.Background()
	var lastID int64
	if rows, err := h.db.ListRecentActivity(ctx, taskID, 50); err == nil && len(rows) > 0 {
		lastID = rows[0].ID - 1
		if lastID < 0 {
			lastID = 0
		}
	}

	ticker := time.NewTicker(h.interval)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			rows, err := h.db.ListActivityAfter(ctx, taskID, lastID, 200)
			if err != nil {
				continue
			}
			for _, a := range rows {
				lastID = a.ID
				h.broadcast(taskID, a)
			}
		}
	}
}

func (h *sseHub) broadcast(taskID int64, a db.Activity) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for ch := range h.subs[taskID] {
		select {
		case ch <- a:
		default:
			// 慢客户端：丢弃本批，避免阻塞其它订阅者
		}
	}
}
