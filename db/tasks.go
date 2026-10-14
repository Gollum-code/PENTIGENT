package db

import (
	"context"
	"fmt"
)

type Task struct {
	ID          int64  `json:"id"`
	Name        string `json:"name"`
	Goal        string `json:"goal"`
	Description string `json:"description"`
	Notes       string `json:"notes,omitempty"`
	CompanyID   *int64 `json:"company_id,omitempty"`
	Status      string `json:"status"`
	Error       string `json:"error,omitempty"`
	CreatedAt   string `json:"created_at,omitempty"`
	StartedAt   string `json:"started_at,omitempty"`
	FinishedAt  string `json:"finished_at,omitempty"`
	// 聚合统计
	Findings int `json:"findings"`
	Assets   int `json:"assets"`
	TokensIn int `json:"tokens_in"`
	TokensOut int `json:"tokens_out"`
}

func (d *DB) CreateTask(ctx context.Context, name, goal, description string, companyID *int64) (int64, error) {
	var id int64
	err := d.pool.QueryRow(ctx,
		`INSERT INTO tasks (name, goal, description, company_id) VALUES ($1,$2,$3,$4) RETURNING id`,
		name, goal, description, companyID).Scan(&id)
	return id, err
}

// SetTaskNotes 更新任务备注/标签
func (d *DB) SetTaskNotes(ctx context.Context, id int64, notes string) error {
	_, err := d.pool.Exec(ctx, `UPDATE tasks SET notes=$2 WHERE id=$1`, id, notes)
	return err
}

// ResetAllData 清空全部演示数据（任务/探索/资产/漏洞/活动/审批），保留规则与配置
func (d *DB) ResetAllData(ctx context.Context) error {
	tables := []string{
		"intercept_pending", "findings", "exploration_anchors", "exploration_edges",
		"exploration_nodes", "explorations", "task_scope", "task_constraints",
		"tasks", "activity", "assets", "companies",
	}
	for _, t := range tables {
		if _, err := d.pool.Exec(ctx, "TRUNCATE "+t+" RESTART IDENTITY CASCADE"); err != nil {
			return err
		}
	}
	return nil
}

// CloneTask 复制任务（新任务 + 复制 scope/notes），返回新任务 id
func (d *DB) CloneTask(ctx context.Context, srcID int64, newName, newGoal string) (int64, error) {
	src, err := d.GetTask(ctx, srcID)
	if err != nil {
		return 0, err
	}
	if newName == "" {
		newName = src.Name + " (副本)"
	}
	if newGoal == "" {
		newGoal = src.Goal
	}
	tid, err := d.CreateTask(ctx, newName, newGoal, src.Description, src.CompanyID)
	if err != nil {
		return 0, err
	}
	// 复制 scope
	scopes, err := d.ListScope(ctx, srcID)
	if err != nil {
		return 0, err
	}
	for _, s := range scopes {
		if err := d.AddScope(ctx, tid, s.Pattern, s.Kind); err != nil {
			return 0, err
		}
	}
	// 复制备注
	if src.Notes != "" {
		if err := d.SetTaskNotes(ctx, tid, src.Notes); err != nil {
			return 0, err
		}
	}
	return tid, nil
}

func (d *DB) GetTask(ctx context.Context, id int64) (*Task, error) {
	var t Task
	err := d.pool.QueryRow(ctx,
		`SELECT t.id, t.name, t.goal, t.description, t.notes, t.company_id, t.status, t.error, t.created_at::text,
		        COALESCE(t.started_at::text,''), COALESCE(t.finished_at::text,''),
		        COALESCE((SELECT SUM(a.input_tokens) FROM activity a WHERE a.task_id=t.id),0)::int,
		        COALESCE((SELECT SUM(a.output_tokens) FROM activity a WHERE a.task_id=t.id),0)::int
		 FROM tasks t WHERE t.id=$1`, id).
		Scan(&t.ID, &t.Name, &t.Goal, &t.Description, &t.Notes, &t.CompanyID, &t.Status, &t.Error, &t.CreatedAt, &t.StartedAt, &t.FinishedAt, &t.TokensIn, &t.TokensOut)
	if err != nil {
		return nil, err
	}
	return &t, nil
}

// ListTasks 任务分页列表。status/q 可为空；返回 (tasks, totalCount)
func (d *DB) ListTasks(ctx context.Context, status, q string, limit, offset int) ([]Task, int, error) {
	if limit <= 0 {
		limit = 50
	}
	if offset < 0 {
		offset = 0
	}
	where := `WHERE TRUE`
	var args []any
	idx := 1
	if status != "" {
		args = append(args, status)
		where += fmt.Sprintf(" AND t.status=$%d", idx)
		idx++
	}
	if q != "" {
		args = append(args, "%"+q+"%")
		where += fmt.Sprintf(" AND (t.name ILIKE $%d OR t.goal ILIKE $%d OR t.description ILIKE $%d)", idx, idx, idx)
		idx++
	}

	// 总数
	var total int
	if err := d.pool.QueryRow(ctx, `SELECT COUNT(*) FROM tasks t `+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	sql := `SELECT t.id, t.name, t.goal, t.description, t.notes, t.company_id, t.status, t.error, t.created_at::text,
		        COALESCE(t.started_at::text,''), COALESCE(t.finished_at::text,''),
		        COALESCE((SELECT COUNT(*) FROM findings f WHERE f.task_id=t.id),0)::int,
		        COALESCE((SELECT COUNT(*) FROM exploration_anchors a JOIN explorations e ON e.id=a.exploration_id WHERE e.task_id=t.id),0)::int,
		        COALESCE((SELECT SUM(ac.input_tokens) FROM activity ac WHERE ac.task_id=t.id),0)::int,
		        COALESCE((SELECT SUM(ac.output_tokens) FROM activity ac WHERE ac.task_id=t.id),0)::int
		 FROM tasks t ` + where + fmt.Sprintf(" ORDER BY t.id DESC LIMIT $%d OFFSET $%d", idx, idx+1)
	args = append(args, limit, offset)
	rows, err := d.pool.Query(ctx, sql, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []Task
	for rows.Next() {
		var t Task
		if err := rows.Scan(&t.ID, &t.Name, &t.Goal, &t.Description, &t.Notes, &t.CompanyID, &t.Status, &t.Error,
			&t.CreatedAt, &t.StartedAt, &t.FinishedAt, &t.Findings, &t.Assets, &t.TokensIn, &t.TokensOut); err != nil {
			return nil, 0, err
		}
		out = append(out, t)
	}
	return out, total, rows.Err()
}

func (d *DB) SetTaskStatus(ctx context.Context, id int64, status, errMsg string) error {
	_, err := d.pool.Exec(ctx,
		`UPDATE tasks SET status=$2, error=$3,
		  started_at = CASE WHEN $2='running' AND started_at IS NULL THEN now() ELSE started_at END,
		  finished_at = CASE WHEN $2 IN ('done','failed','stopped') THEN now() ELSE finished_at END
		 WHERE id=$1`, id, status, errMsg)
	return err
}

func (d *DB) DeleteTask(ctx context.Context, id int64) error {
	// 级联清理探索图
	var explIDs []int64
	rows, err := d.pool.Query(ctx, `SELECT id FROM explorations WHERE task_id=$1`, id)
	if err != nil {
		return err
	}
	for rows.Next() {
		var e int64
		if err := rows.Scan(&e); err != nil {
			rows.Close()
			return err
		}
		explIDs = append(explIDs, e)
	}
	rows.Close()
	for _, eid := range explIDs {
		if _, err := d.pool.Exec(ctx, `DELETE FROM explorations WHERE id=$1`, eid); err != nil {
			return err
		}
	}
	if _, err := d.pool.Exec(ctx, `DELETE FROM tasks WHERE id=$1`, id); err != nil {
		return err
	}
	if _, err := d.pool.Exec(ctx, `DELETE FROM activity WHERE task_id=$1`, id); err != nil {
		return err
	}
	if _, err := d.pool.Exec(ctx, `DELETE FROM intercept_pending WHERE task_id=$1`, id); err != nil {
		return err
	}
	_, err = d.pool.Exec(ctx, `DELETE FROM task_scope WHERE task_id=$1`, id)
	return err
}

// Stats 全局统计
type Stats struct {
	TasksTotal         int            `json:"tasks_total"`
	TasksRunning       int            `json:"tasks_running"`
	TasksDone          int            `json:"tasks_done"`
	FindingsTotal      int            `json:"findings_total"`
	FindingsBySeverity map[string]int `json:"findings_by_severity"`
	AssetsTotal        int            `json:"assets_total"`
	TokensIn           int            `json:"tokens_in"`
	TokensOut          int            `json:"tokens_out"`
}

func (d *DB) GetStats(ctx context.Context) (*Stats, error) {
	st := &Stats{FindingsBySeverity: map[string]int{}}
	// 任务数
	_ = d.pool.QueryRow(ctx,
		`SELECT
		   COUNT(*)::int,
		   COUNT(*) FILTER (WHERE status='running')::int,
		   COUNT(*) FILTER (WHERE status='done')::int
		 FROM tasks`).Scan(&st.TasksTotal, &st.TasksRunning, &st.TasksDone)
	// 漏洞总数 + 按严重性
	rows, err := d.pool.Query(ctx,
		`SELECT severity, COUNT(*)::int FROM findings GROUP BY severity`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var sev string
		var n int
		if err := rows.Scan(&sev, &n); err != nil {
			rows.Close()
			return nil, err
		}
		st.FindingsTotal += n
		st.FindingsBySeverity[sev] = n
	}
	rows.Close()
	// 资产数
	_ = d.pool.QueryRow(ctx, `SELECT COUNT(*)::int FROM assets`).Scan(&st.AssetsTotal)
	// token 消耗
	_ = d.pool.QueryRow(ctx,
		`SELECT COALESCE(SUM(input_tokens),0)::int, COALESCE(SUM(output_tokens),0)::int FROM activity`).
		Scan(&st.TokensIn, &st.TokensOut)
	return st, nil
}

// ---- task_scope ----

func (d *DB) AddScope(ctx context.Context, taskID int64, pattern, kind string) error {
	_, err := d.pool.Exec(ctx,
		`INSERT INTO task_scope (task_id, pattern, kind) VALUES ($1,$2,$3)
		 ON CONFLICT DO NOTHING`, taskID, pattern, kind)
	return err
}

func (d *DB) ListScope(ctx context.Context, taskID int64) ([]ScopeItem, error) {
	rows, err := d.pool.Query(ctx,
		`SELECT pattern, kind FROM task_scope WHERE task_id=$1 ORDER BY id`, taskID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ScopeItem
	for rows.Next() {
		var s ScopeItem
		if err := rows.Scan(&s.Pattern, &s.Kind); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

type ScopeItem struct {
	Pattern string `json:"pattern"`
	Kind    string `json:"kind"`
}

// ---- constraints ----

func (d *DB) AddConstraint(ctx context.Context, taskID int64, kind, pattern string) error {
	_, err := d.pool.Exec(ctx,
		`INSERT INTO task_constraints (task_id, kind, pattern) VALUES ($1,$2,$3)
		 ON CONFLICT DO NOTHING`, taskID, kind, pattern)
	return err
}

func (d *DB) ListConstraints(ctx context.Context, taskID int64) ([]struct {
	Kind    string `json:"kind"`
	Pattern string `json:"pattern"`
}, error) {
	rows, err := d.pool.Query(ctx,
		`SELECT kind, pattern FROM task_constraints WHERE task_id=$1 ORDER BY id`, taskID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []struct {
		Kind    string `json:"kind"`
		Pattern string `json:"pattern"`
	}
	for rows.Next() {
		var k, p string
		if err := rows.Scan(&k, &p); err != nil {
			return nil, err
		}
		out = append(out, struct {
			Kind    string `json:"kind"`
			Pattern string `json:"pattern"`
		}{k, p})
	}
	return out, rows.Err()
}

// ---- activity ----

type Activity struct {
	ID           int64          `json:"id"`
	TaskID       *int64         `json:"task_id,omitempty"`
	ExplorationID *int64        `json:"exploration_id,omitempty"`
	NodeID       *int64         `json:"node_id,omitempty"`
	Role         string         `json:"role"`
	Step         string         `json:"step"`
	Tool         string         `json:"tool,omitempty"`
	Input        map[string]any `json:"input,omitempty"`
	Output       map[string]any `json:"output,omitempty"`
	Status       string         `json:"status"`
	InputTokens  int            `json:"input_tokens"`
	OutputTokens int            `json:"output_tokens"`
	CreatedAt    string         `json:"created_at,omitempty"`
}

func (d *DB) LogActivity(ctx context.Context, a Activity) (int64, error) {
	// JSONB 列是 NOT NULL：nil map 必须兜底成 {}
	if a.Input == nil {
		a.Input = map[string]any{}
	}
	if a.Output == nil {
		a.Output = map[string]any{}
	}
	var id int64
	err := d.pool.QueryRow(ctx,
		`INSERT INTO activity (task_id, exploration_id, node_id, role, step, tool, input, output, status, input_tokens, output_tokens)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) RETURNING id`,
		a.TaskID, a.ExplorationID, a.NodeID, a.Role, a.Step, a.Tool, a.Input, a.Output, a.Status, a.InputTokens, a.OutputTokens).Scan(&id)
	return id, err
}

// ListActivityAfter 用于 SSE 增量拉取
func (d *DB) ListActivityAfter(ctx context.Context, taskID int64, afterID int64, limit int) ([]Activity, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := d.pool.Query(ctx,
		`SELECT id, task_id, exploration_id, node_id, role, step, tool, input, output, status, input_tokens, output_tokens, created_at::text
		 FROM activity WHERE task_id=$1 AND id>$2 ORDER BY id ASC LIMIT $3`, taskID, afterID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Activity
	for rows.Next() {
		var a Activity
		if err := rows.Scan(&a.ID, &a.TaskID, &a.ExplorationID, &a.NodeID, &a.Role, &a.Step, &a.Tool,
			&a.Input, &a.Output, &a.Status, &a.InputTokens, &a.OutputTokens, &a.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// ListRecentActivity 取任务最近 N 条活动（按 id 升序返回，便于顺序展示）
func (d *DB) ListRecentActivity(ctx context.Context, taskID int64, limit int) ([]Activity, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := d.pool.Query(ctx,
		`SELECT id, task_id, exploration_id, node_id, role, step, tool, input, output, status, input_tokens, output_tokens, created_at::text
		 FROM (SELECT * FROM activity WHERE task_id=$1 ORDER BY id DESC LIMIT $2) t
		 ORDER BY id ASC`, taskID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Activity
	for rows.Next() {
		var a Activity
		if err := rows.Scan(&a.ID, &a.TaskID, &a.ExplorationID, &a.NodeID, &a.Role, &a.Step, &a.Tool,
			&a.Input, &a.Output, &a.Status, &a.InputTokens, &a.OutputTokens, &a.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// SearchWorkerTraces worker 间过程级信息交换：搜其他 worker 的执行观察
func (d *DB) SearchWorkerTraces(ctx context.Context, taskID int64, q string, limit int) ([]Activity, error) {
	if limit <= 0 {
		limit = 30
	}
	rows, err := d.pool.Query(ctx,
		`SELECT id, task_id, exploration_id, node_id, role, step, tool, input, output, status, input_tokens, output_tokens, created_at::text
		 FROM activity
		 WHERE task_id=$1 AND role='worker'
		   AND (step ILIKE $2 OR output::text ILIKE $2)
		 ORDER BY id DESC LIMIT $3`, taskID, "%"+q+"%", limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Activity
	for rows.Next() {
		var a Activity
		if err := rows.Scan(&a.ID, &a.TaskID, &a.ExplorationID, &a.NodeID, &a.Role, &a.Step, &a.Tool,
			&a.Input, &a.Output, &a.Status, &a.InputTokens, &a.OutputTokens, &a.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// GetWorkerTrace 取某 worker 意图的完整执行步骤
func (d *DB) GetWorkerTrace(ctx context.Context, intentID int64, limit int) ([]Activity, error) {
	if limit <= 0 {
		limit = 200
	}
	rows, err := d.pool.Query(ctx,
		`SELECT id, task_id, exploration_id, node_id, role, step, tool, input, output, status, input_tokens, output_tokens, created_at::text
		 FROM activity WHERE node_id=$1 ORDER BY id ASC LIMIT $2`, intentID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Activity
	for rows.Next() {
		var a Activity
		if err := rows.Scan(&a.ID, &a.TaskID, &a.ExplorationID, &a.NodeID, &a.Role, &a.Step, &a.Tool,
			&a.Input, &a.Output, &a.Status, &a.InputTokens, &a.OutputTokens, &a.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}