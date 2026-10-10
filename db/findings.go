package db

import (
	"context"
	"fmt"
)

type Finding struct {
	ID           int64          `json:"id"`
	TaskID       *int64         `json:"task_id,omitempty"`
	TaskName     string         `json:"task_name,omitempty"`
	ExplorationID *int64        `json:"exploration_id,omitempty"`
	NodeID       *int64         `json:"node_id,omitempty"`
	AssetID      *int64         `json:"asset_id,omitempty"`
	Title        string         `json:"title"`
	Severity     string         `json:"severity"`
	Status       string         `json:"status"`
	Evidence     map[string]any `json:"evidence,omitempty"`
	CreatedAt    string         `json:"created_at,omitempty"`
}

// ReportFinding 写漏洞节点：先去重（同 title+task 已存在则返回既有）
func (d *DB) ReportFinding(ctx context.Context, f Finding) (int64, bool, error) {
	if f.Evidence == nil {
		f.Evidence = map[string]any{}
	}
	var id int64
	err := d.pool.QueryRow(ctx,
		`INSERT INTO findings (task_id, exploration_id, node_id, asset_id, title, severity, status, evidence)
		 VALUES ($1::bigint,$2::bigint,$3::bigint,$4::bigint,$5::text,$6::text,$7::text,$8::jsonb)
		 ON CONFLICT (task_id, title) WHERE task_id IS NOT NULL DO NOTHING RETURNING id`,
		f.TaskID, f.ExplorationID, f.NodeID, f.AssetID, f.Title, f.Severity, f.Status, f.Evidence).Scan(&id)
	if err == nil {
		return id, true, nil
	}
	// 冲突 → 查已有
	var existing int64
	err2 := d.pool.QueryRow(ctx,
		`SELECT id FROM findings WHERE task_id=$1 AND title=$2 ORDER BY id DESC LIMIT 1`,
		f.TaskID, f.Title).Scan(&existing)
	if err2 == nil {
		return existing, false, nil
	}
	return 0, false, err
}

func (d *DB) ListFindings(ctx context.Context, taskID *int64, severity, status string, limit, offset int) ([]Finding, int, error) {
	if limit <= 0 {
		limit = 100
	}
	if offset < 0 {
		offset = 0
	}
	where := `WHERE TRUE`
	var args []any
	idx := 1
	if taskID != nil {
		args = append(args, *taskID)
		where += fmt.Sprintf(" AND f.task_id=$%d", idx)
		idx++
	}
	if severity != "" {
		args = append(args, severity)
		where += fmt.Sprintf(" AND f.severity=$%d", idx)
		idx++
	}
	if status != "" {
		args = append(args, status)
		where += fmt.Sprintf(" AND f.status=$%d", idx)
		idx++
	}

	// 总数
	var total int
	if err := d.pool.QueryRow(ctx, `SELECT COUNT(*) FROM findings f `+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	sql := `SELECT f.id, f.task_id, COALESCE(t.name,'') AS task_name, f.exploration_id, f.node_id, f.asset_id,
			f.title, f.severity, f.status, f.evidence, f.created_at::text
		FROM findings f LEFT JOIN tasks t ON t.id=f.task_id ` + where + fmt.Sprintf(" ORDER BY f.id DESC LIMIT $%d OFFSET $%d", idx, idx+1)
	args = append(args, limit, offset)
	rows, err := d.pool.Query(ctx, sql, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []Finding
	for rows.Next() {
		var f Finding
		if err := rows.Scan(&f.ID, &f.TaskID, &f.TaskName, &f.ExplorationID, &f.NodeID, &f.AssetID, &f.Title,
			&f.Severity, &f.Status, &f.Evidence, &f.CreatedAt); err != nil {
			return nil, 0, err
		}
		out = append(out, f)
	}
	return out, total, rows.Err()
}

func (d *DB) SetFindingStatus(ctx context.Context, id int64, status string) error {
	_, err := d.pool.Exec(ctx, `UPDATE findings SET status=$2 WHERE id=$1`, id, status)
	return err
}

// DeleteFinding 删除单个漏洞记录
func (d *DB) DeleteFinding(ctx context.Context, id int64) error {
	_, err := d.pool.Exec(ctx, `DELETE FROM findings WHERE id=$1`, id)
	return err
}

// ---- intercept ----

type InterceptRule struct {
	ID          int64  `json:"id"`
	Name        string `json:"name"`
	MatchTarget string `json:"match_target"`
	MatchType   string `json:"match_type"`
	Pattern     string `json:"pattern"`
	Action      string `json:"action"`
	Priority    int    `json:"priority"`
	Enabled     bool   `json:"enabled"`
}

type PendingIntercept struct {
	ID          int64          `json:"id"`
	TaskID      *int64         `json:"task_id,omitempty"`
	TaskName    string         `json:"task_name,omitempty"` // 审批上下文：任务名
	NodeID      *int64         `json:"node_id,omitempty"`
	IntentTitle string         `json:"intent_title,omitempty"` // 审批上下文：意图标题
	Tool        string         `json:"tool"`
	Input       map[string]any `json:"input"`
	RuleID      *int64         `json:"rule_id,omitempty"`
	Reason      string         `json:"reason"`
	Status      string         `json:"status"`
	CreatedAt   string         `json:"created_at,omitempty"`
}

func (d *DB) ListRules(ctx context.Context) ([]InterceptRule, error) {
	rows, err := d.pool.Query(ctx,
		`SELECT id, name, match_target, match_type, pattern, action, priority, enabled
		 FROM intercept_rules ORDER BY priority ASC, id ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []InterceptRule
	for rows.Next() {
		var r InterceptRule
		if err := rows.Scan(&r.ID, &r.Name, &r.MatchTarget, &r.MatchType, &r.Pattern, &r.Action, &r.Priority, &r.Enabled); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (d *DB) CreateRule(ctx context.Context, r InterceptRule) (int64, error) {
	var id int64
	err := d.pool.QueryRow(ctx,
		`INSERT INTO intercept_rules (name, match_target, match_type, pattern, action, priority, enabled)
		 VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING id`,
		r.Name, r.MatchTarget, r.MatchType, r.Pattern, r.Action, r.Priority, r.Enabled).Scan(&id)
	return id, err
}

// DeleteRule 删除审批规则
func (d *DB) DeleteRule(ctx context.Context, id int64) error {
	_, err := d.pool.Exec(ctx, `DELETE FROM intercept_rules WHERE id=$1`, id)
	return err
}

func (d *DB) EnqueueIntercept(ctx context.Context, p PendingIntercept) (int64, error) {
	var id int64
	err := d.pool.QueryRow(ctx,
		`INSERT INTO intercept_pending (task_id, node_id, tool, input, rule_id, reason)
		 VALUES ($1,$2,$3,$4,$5,$6) RETURNING id`,
		p.TaskID, p.NodeID, p.Tool, p.Input, p.RuleID, p.Reason).Scan(&id)
	return id, err
}

func (d *DB) ListPending(ctx context.Context, status string, limit int) ([]PendingIntercept, error) {
	if limit <= 0 {
		limit = 100
	}
	sql := `SELECT p.id, p.task_id, COALESCE(t.name,'') AS task_name, p.node_id,
			COALESCE(n.title,'') AS intent_title, p.tool, p.input, p.rule_id, p.reason, p.status, p.created_at::text
		FROM intercept_pending p
		LEFT JOIN tasks t ON t.id = p.task_id
		LEFT JOIN exploration_nodes n ON n.id = p.node_id
		WHERE TRUE`
	var args []any
	if status != "" {
		args = append(args, status)
		sql += " AND p.status=$1"
	}
	args = append(args, limit)
	sql += " ORDER BY p.id DESC LIMIT $2"
	rows, err := d.pool.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []PendingIntercept
	for rows.Next() {
		var p PendingIntercept
		if err := rows.Scan(&p.ID, &p.TaskID, &p.TaskName, &p.NodeID, &p.IntentTitle, &p.Tool, &p.Input, &p.RuleID, &p.Reason, &p.Status, &p.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func (d *DB) GetPending(ctx context.Context, id int64) (*PendingIntercept, error) {
	var p PendingIntercept
	err := d.pool.QueryRow(ctx,
		`SELECT id, task_id, node_id, tool, input, rule_id, reason, status, created_at
		 FROM intercept_pending WHERE id=$1`, id).
		Scan(&p.ID, &p.TaskID, &p.NodeID, &p.Tool, &p.Input, &p.RuleID, &p.Reason, &p.Status, &p.CreatedAt)
	if err != nil {
		return nil, err
	}
	return &p, nil
}

func (d *DB) DecidePending(ctx context.Context, id int64, approved bool) error {
	status := "denied"
	if approved {
		status = "approved"
	}
	_, err := d.pool.Exec(ctx,
		`UPDATE intercept_pending SET status=$2, decided_at=now() WHERE id=$1`, id, status)
	return err
}

func (d *DB) ListAssetRules(ctx context.Context) ([]AssetRule, error) {
	rows, err := d.pool.Query(ctx,
		`SELECT pattern, action, note FROM asset_intercept_rules ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AssetRule
	for rows.Next() {
		var r AssetRule
		if err := rows.Scan(&r.Pattern, &r.Action, &r.Note); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

type AssetRule struct {
	Pattern string `json:"pattern"`
	Action  string `json:"action"`
	Note    string `json:"note"`
}