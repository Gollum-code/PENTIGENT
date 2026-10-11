package db

import (
	"context"
	"strings"
)

// TaskTemplate 预置/自定义任务模板
type TaskTemplate struct {
	ID          int64  `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Goal        string `json:"goal"`
	TaskDesc    string `json:"task_desc"`
	Scope       string `json:"scope"`
	Tags        string `json:"tags"`
	Builtin     bool   `json:"builtin"`
}

// 内置模板的 seed 数据在 schema.sql 里以 INSERT ... ON CONFLICT DO NOTHING 维护

func (d *DB) ListTaskTemplates(ctx context.Context) ([]TaskTemplate, error) {
	rows, err := d.pool.Query(ctx,
		`SELECT id, name, description, goal, task_desc, scope, tags, builtin
		 FROM task_templates ORDER BY builtin DESC, id ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []TaskTemplate{}
	for rows.Next() {
		var t TaskTemplate
		if err := rows.Scan(&t.ID, &t.Name, &t.Description, &t.Goal, &t.TaskDesc, &t.Scope, &t.Tags, &t.Builtin); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

func (d *DB) CreateTaskTemplate(ctx context.Context, t TaskTemplate) (int64, error) {
	var id int64
	err := d.pool.QueryRow(ctx,
		`INSERT INTO task_templates (name, description, goal, task_desc, scope, tags, builtin)
		 VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING id`,
		t.Name, t.Description, t.Goal, t.TaskDesc, t.Scope, t.Tags, t.Builtin).Scan(&id)
	return id, err
}

func (d *DB) DeleteTaskTemplate(ctx context.Context, id int64) error {
	// 内置模板不可删
	_, err := d.pool.Exec(ctx, `DELETE FROM task_templates WHERE id=$1 AND builtin=FALSE`, id)
	return err
}

func (d *DB) UpdateTaskTemplate(ctx context.Context, id int64, t TaskTemplate) error {
	_, err := d.pool.Exec(ctx,
		`UPDATE task_templates SET name=$2, description=$3, goal=$4, task_desc=$5, scope=$6, tags=$7
		 WHERE id=$1 AND builtin=FALSE`, id, t.Name, t.Description, t.Goal, t.TaskDesc, t.Scope, t.Tags)
	return err
}

// ScopeList 模板 scope 字符串 → []string
func (t TaskTemplate) ScopeList() []string {
	if strings.TrimSpace(t.Scope) == "" {
		return nil
	}
	parts := strings.Split(t.Scope, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if s := strings.TrimSpace(p); s != "" {
			out = append(out, s)
		}
	}
	return out
}

// ---- 报告设置 ----

type ReportSettings struct {
	OrgName       string `json:"org_name"`
	ReportTitle   string `json:"report_title"`
	LogoURL       string `json:"logo_url"`
	ShowAssets    bool   `json:"show_assets"`
	ShowFacts     bool   `json:"show_facts"`
	ShowCoverage  bool   `json:"show_coverage"`
	MinSeverity   string `json:"min_severity"`
	ConfirmedOnly bool   `json:"confirmed_only"`
	Footer        string `json:"footer"`
}

func (d *DB) GetReportSettings(ctx context.Context) (*ReportSettings, error) {
	var r ReportSettings
	err := d.pool.QueryRow(ctx,
		`SELECT org_name, report_title, logo_url, show_assets, show_facts, show_coverage,
		        min_severity, confirmed_only, footer
		 FROM report_settings WHERE id=1`).Scan(
		&r.OrgName, &r.ReportTitle, &r.LogoURL, &r.ShowAssets, &r.ShowFacts, &r.ShowCoverage,
		&r.MinSeverity, &r.ConfirmedOnly, &r.Footer)
	if err != nil {
		return nil, err
	}
	return &r, nil
}

func (d *DB) UpdateReportSettings(ctx context.Context, r ReportSettings) error {
	_, err := d.pool.Exec(ctx,
		`UPDATE report_settings SET org_name=$1, report_title=$2, logo_url=$3,
		   show_assets=$4, show_facts=$5, show_coverage=$6, min_severity=$7,
		   confirmed_only=$8, footer=$9, updated_at=now()
		 WHERE id=1`,
		r.OrgName, r.ReportTitle, r.LogoURL, r.ShowAssets, r.ShowFacts, r.ShowCoverage,
		r.MinSeverity, r.ConfirmedOnly, r.Footer)
	return err
}