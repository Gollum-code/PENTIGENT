package db

import (
	"context"
	"encoding/json"
	"time"

	"github.com/jackc/pgx/v5"
)

type Node struct {
	ID          int64          `json:"id"`
	ExplorationID int64        `json:"exploration_id"`
	Type        string         `json:"type"`
	Status      string         `json:"status"`
	Title       string         `json:"title"`
	Content     map[string]any `json:"content,omitempty"`
	WorkerID    string         `json:"worker_id,omitempty"`
	CreatedAt   string         `json:"created_at,omitempty"`
}

type Edge struct {
	ID           int64  `json:"id"`
	FromNodeID   int64  `json:"from_node_id"`
	ToNodeID     int64  `json:"to_node_id"`
	Relation     string `json:"relation"`
}

type Exploration struct {
	ID        int64           `json:"id"`
	TaskID    *int64          `json:"task_id,omitempty"`
	Goal      string          `json:"goal"`
	Status    string          `json:"status"`
	Todolist  json.RawMessage `json:"todolist"`
	CreatedAt string          `json:"created_at,omitempty"`
}

// ExplorationForTask 找任务最近的探索
func (d *DB) ExplorationForTask(ctx context.Context, taskID int64) (int64, error) {
	var id int64
	err := d.pool.QueryRow(ctx,
		`SELECT id FROM explorations WHERE task_id=$1 ORDER BY id DESC LIMIT 1`, taskID).Scan(&id)
	return id, err
}

// SetExplorationStatusForTask 把任务最近的探索设为某状态（如 paused）
func (d *DB) SetExplorationStatusForTask(ctx context.Context, taskID int64, status string) error {
	eid, err := d.ExplorationForTask(ctx, taskID)
	if err != nil {
		return err
	}
	return d.SetExplorationStatus(ctx, eid, status)
}

func (d *DB) CreateExploration(ctx context.Context, taskID int64, goal string) (int64, error) {
	var id int64
	err := d.pool.QueryRow(ctx,
		`INSERT INTO explorations (task_id, goal) VALUES ($1,$2) RETURNING id`,
		taskID, goal).Scan(&id)
	return id, err
}

func (d *DB) GetExploration(ctx context.Context, id int64) (*Exploration, error) {
	var e Exploration
	err := d.pool.QueryRow(ctx,
		`SELECT id, task_id, goal, status, todolist, created_at::text FROM explorations WHERE id=$1`, id).
		Scan(&e.ID, &e.TaskID, &e.Goal, &e.Status, &e.Todolist, &e.CreatedAt)
	if err != nil {
		return nil, err
	}
	return &e, nil
}

func (d *DB) GetTodolist(ctx context.Context, explorationID int64) ([]string, error) {
	var raw json.RawMessage
	err := d.pool.QueryRow(ctx, `SELECT todolist FROM explorations WHERE id=$1`, explorationID).Scan(&raw)
	if err != nil {
		return nil, err
	}
	var list []string
	if err := json.Unmarshal(raw, &list); err != nil {
		return nil, err
	}
	return list, nil
}

func (d *DB) SetTodolist(ctx context.Context, explorationID int64, list []string) error {
	raw, err := json.Marshal(list)
	if err != nil {
		return err
	}
	_, err = d.pool.Exec(ctx,
		`UPDATE explorations SET todolist=$2, updated_at=now() WHERE id=$1`, explorationID, raw)
	return err
}

func (d *DB) SetExplorationStatus(ctx context.Context, id int64, status string) error {
	_, err := d.pool.Exec(ctx,
		`UPDATE explorations SET status=$2, updated_at=now() WHERE id=$1`, id, status)
	return err
}

// CreateNode 插入节点并返回 id
func (d *DB) CreateNode(ctx context.Context, explorationID int64, typ, status, title string, content map[string]any) (int64, error) {
	var id int64
	err := d.pool.QueryRow(ctx,
		`INSERT INTO exploration_nodes (exploration_id, type, status, title, content)
		 VALUES ($1,$2,$3,$4,$5) RETURNING id`,
		explorationID, typ, status, title, content).Scan(&id)
	return id, err
}

func (d *DB) GetNode(ctx context.Context, id int64) (*Node, error) {
	var n Node
	err := d.pool.QueryRow(ctx,
		`SELECT id, exploration_id, type, status, title, content, COALESCE(worker_id,''), created_at::text
		 FROM exploration_nodes WHERE id=$1`, id).
		Scan(&n.ID, &n.ExplorationID, &n.Type, &n.Status, &n.Title, &n.Content, &n.WorkerID, &n.CreatedAt)
	if err != nil {
		return nil, err
	}
	return &n, nil
}

func (d *DB) SetNodeStatus(ctx context.Context, id int64, status string) error {
	_, err := d.pool.Exec(ctx,
		`UPDATE exploration_nodes SET status=$2, updated_at=now() WHERE id=$1`, id, status)
	return err
}

// ClaimNextIntent worker 领一条 open 的 intent（并发安全）
func (d *DB) ClaimNextIntent(ctx context.Context, explorationID int64, workerID string) (*Node, error) {
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	var id int64
	err = tx.QueryRow(ctx,
		`SELECT id FROM exploration_nodes
		 WHERE exploration_id=$1 AND type='intent' AND status='open'
		 ORDER BY id ASC LIMIT 1
		 FOR UPDATE SKIP LOCKED`, explorationID).Scan(&id)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if _, err = tx.Exec(ctx,
		`UPDATE exploration_nodes SET status='running', worker_id=$2, claimed_at=now(), updated_at=now() WHERE id=$1`,
		id, workerID); err != nil {
		return nil, err
	}
	if err = tx.Commit(ctx); err != nil {
		return nil, err
	}
	return d.GetNode(ctx, id)
}

// ReclaimStuckIntents 回收超时未完成的 intent（worker 崩溃/进程被杀）。
// 把 claimed_at 超过 timeout 的 running intent 重置为 open，使其可被重新领取。
// 返回回收数量。
func (d *DB) ReclaimStuckIntents(ctx context.Context, explorationID int64, timeout time.Duration) (int, error) {
	cutoff := time.Now().Add(-timeout)
	tag, err := d.pool.Exec(ctx,
		`UPDATE exploration_nodes
		 SET status='open', worker_id=NULL, claimed_at=NULL, updated_at=now()
		 WHERE exploration_id=$1 AND type='intent' AND status='running'
		   AND claimed_at IS NOT NULL AND claimed_at < $2`,
		explorationID, cutoff)
	if err != nil {
		return 0, err
	}
	return int(tag.RowsAffected()), nil
}

// ResetRunningIntents 把该探索下所有 running 的 intent 重置为 open。
// 用于断点续跑：暂停/停止时执行中的 worker 已终止，其 running intent 需要重新入队。
// 返回重置数量。
func (d *DB) ResetRunningIntents(ctx context.Context, explorationID int64) (int, error) {
	tag, err := d.pool.Exec(ctx,
		`UPDATE exploration_nodes
		 SET status='open', worker_id=NULL, claimed_at=NULL, updated_at=now()
		 WHERE exploration_id=$1 AND type='intent' AND status='running'`,
		explorationID)
	if err != nil {
		return 0, err
	}
	return int(tag.RowsAffected()), nil
}

// ListNodes 按类型/状态过滤
func (d *DB) ListNodes(ctx context.Context, explorationID int64, typ, status string) ([]Node, error) {
	sql := `SELECT id, exploration_id, type, status, title, content, COALESCE(worker_id,''), created_at::text
		FROM exploration_nodes WHERE exploration_id=$1`
	args := []any{explorationID}
	if typ != "" {
		args = append(args, typ)
		sql += " AND type=$2"
	}
	if status != "" {
		args = append(args, status)
		sql += " AND status=$3"
	}
	sql += " ORDER BY id ASC"
	rows, err := d.pool.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Node
	for rows.Next() {
		var n Node
		if err := rows.Scan(&n.ID, &n.ExplorationID, &n.Type, &n.Status, &n.Title, &n.Content, &n.WorkerID, &n.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

// HasOpenIntent 判断 frontier 是否还有待办（planner 空闲判定）
func (d *DB) HasOpenIntent(ctx context.Context, explorationID int64) (bool, error) {
	var exists bool
	err := d.pool.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM exploration_nodes
		 WHERE exploration_id=$1 AND type='intent' AND status IN ('open','running'))`,
		explorationID).Scan(&exists)
	return exists, err
}

// AssetCoverage 返回每个资产的测试覆盖：被哪些 intent 测过、产出了哪些 finding。
// 用锚点反查，展示"资产 ↔ 探索"关联。
type AssetCoverage struct {
	AssetID  int64  `json:"asset_id"`
	Type     string `json:"type"`
	Domain   string `json:"domain"`
	URL      string `json:"url"`
	TestedBy []Node `json:"tested_by,omitempty"` // 测过它的 intent 节点
	Findings []Node `json:"findings,omitempty"`  // 关联的 finding 节点
}

func (d *DB) AssetCoverage(ctx context.Context, assetIDs []int64) ([]AssetCoverage, error) {
	out := []AssetCoverage{}
	if len(assetIDs) == 0 {
		return out, nil
	}
	// 资产基本信息
	rows, err := d.pool.Query(ctx,
		`SELECT id, type, COALESCE(domain,''), COALESCE(url,'') FROM assets WHERE id = ANY($1)`, assetIDs)
	if err != nil {
		return nil, err
	}
	idx := map[int64]int{}
	for rows.Next() {
		var ac AssetCoverage
		if err := rows.Scan(&ac.AssetID, &ac.Type, &ac.Domain, &ac.URL); err != nil {
			rows.Close()
			return nil, err
		}
		idx[ac.AssetID] = len(out)
		out = append(out, ac)
	}
	rows.Close()

	// 锚点反查：该资产被哪些 intent / finding 节点测过
	nodes, err := d.pool.Query(ctx,
		`SELECT a.asset_id, n.id, n.type, n.status, n.title, n.exploration_id
		 FROM exploration_anchors a
		 JOIN exploration_nodes n ON n.id = a.node_id
		 WHERE a.asset_id = ANY($1)
		 ORDER BY n.id`, assetIDs)
	if err != nil {
		return nil, err
	}
	defer nodes.Close()
	for nodes.Next() {
		var assetID int64
		var id, explID int64
		var typ, status, title string
		if err := nodes.Scan(&assetID, &id, &typ, &status, &title, &explID); err != nil {
			return nil, err
		}
		pos, ok := idx[assetID]
		if !ok {
			continue
		}
		n := Node{ID: id, Type: typ, Status: status, Title: title, ExplorationID: explID}
		if typ == "finding" {
			out[pos].Findings = append(out[pos].Findings, n)
		} else if typ == "intent" {
			out[pos].TestedBy = append(out[pos].TestedBy, n)
		}
	}
	return out, nodes.Err()
}

func (d *DB) AddEdge(ctx context.Context, explorationID, fromID, toID int64, relation string) error {
	_, err := d.pool.Exec(ctx,
		`INSERT INTO exploration_edges (exploration_id, from_node_id, to_node_id, relation)
		 VALUES ($1,$2,$3,$4) ON CONFLICT DO NOTHING`,
		explorationID, fromID, toID, relation)
	return err
}

func (d *DB) ListEdges(ctx context.Context, explorationID int64) ([]Edge, error) {
	rows, err := d.pool.Query(ctx,
		`SELECT id, from_node_id, to_node_id, relation FROM exploration_edges WHERE exploration_id=$1 ORDER BY id`,
		explorationID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Edge
	for rows.Next() {
		var e Edge
		if err := rows.Scan(&e.ID, &e.FromNodeID, &e.ToNodeID, &e.Relation); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// Anchor 锚点：探索节点 ↔ 资产
func (d *DB) Anchor(ctx context.Context, explorationID, nodeID, assetID int64) error {
	_, err := d.pool.Exec(ctx,
		`INSERT INTO exploration_anchors (exploration_id, node_id, asset_id)
		 VALUES ($1,$2,$3) ON CONFLICT DO NOTHING`,
		explorationID, nodeID, assetID)
	return err
}

// AnchorsForAssets 反查资产被哪些节点测过
func (d *DB) AnchorsForAssets(ctx context.Context, assetIDs []int64) (map[int64][]int64, error) {
	out := map[int64][]int64{}
	if len(assetIDs) == 0 {
		return out, nil
	}
	rows, err := d.pool.Query(ctx,
		`SELECT asset_id, node_id FROM exploration_anchors WHERE asset_id = ANY($1)`, assetIDs)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var a, n int64
		if err := rows.Scan(&a, &n); err != nil {
			return nil, err
		}
		out[a] = append(out[a], n)
	}
	return out, rows.Err()
}