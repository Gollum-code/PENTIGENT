package db

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
)

type Asset struct {
	ID        int64          `json:"id"`
	CompanyID *int64         `json:"company_id,omitempty"`
	Type      string         `json:"type"`
	RootDomain string        `json:"root_domain,omitempty"`
	Domain    string         `json:"domain,omitempty"`
	RecordType string        `json:"record_type,omitempty"`
	IP        string         `json:"ip,omitempty"`
	AppName   string         `json:"app_name,omitempty"`
	BundleID  string         `json:"bundle_id,omitempty"`
	URL       string         `json:"url,omitempty"`
	Method    string         `json:"method,omitempty"`
	Title     string         `json:"title,omitempty"`
	Extra     map[string]any `json:"extra,omitempty"`
}

// Company 确保公司存在（按名字幂等）
func (d *DB) EnsureCompany(ctx context.Context, name string) (int64, error) {
	var id int64
	err := d.pool.QueryRow(ctx,
		`INSERT INTO companies (name) VALUES ($1)
		 ON CONFLICT (name) DO UPDATE SET name = EXCLUDED.name
		 RETURNING id`, name).Scan(&id)
	return id, err
}

func (d *DB) ListCompanies(ctx context.Context) ([]map[string]any, error) {
	rows, err := d.pool.Query(ctx, `SELECT id, name, created_at FROM companies ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []map[string]any
	for rows.Next() {
		var id int64
		var name string
		var created any
		if err := rows.Scan(&id, &name, &created); err != nil {
			return nil, err
		}
		out = append(out, map[string]any{"id": id, "name": name, "created_at": created})
	}
	return out, rows.Err()
}

// InsertAsset 幂等插入资产：唯一键冲突则返回已有 id
func (d *DB) InsertAsset(ctx context.Context, companyID int64, a Asset) (int64, bool, error) {
	if a.Extra == nil {
		a.Extra = map[string]any{}
	}
	q := `INSERT INTO assets (company_id, type, root_domain, domain, record_type, ip, app_name, bundle_id, url, method, title, extra)
		VALUES ($1::bigint,$2::text,$3::text,$4::text,$5::text,$6::text,$7::text,$8::text,$9::text,$10::text,$11::text,$12::jsonb)
		ON CONFLICT DO NOTHING
		RETURNING id`
	// 用程序算出的唯一键冲突：先按类型查
	var id int64
	err := d.pool.QueryRow(ctx, q,
		companyID, a.Type, a.RootDomain, a.Domain, a.RecordType, a.IP, a.AppName, a.BundleID, a.URL, a.Method, a.Title, a.Extra,
	).Scan(&id)
	if err == nil {
		return id, true, nil
	}
	if err == pgx.ErrNoRows {
		// 唯一键冲突 → 查已有
		id, err = d.findAsset(ctx, companyID, a)
		return id, false, err
	}
	return 0, false, err
}

func (d *DB) findAsset(ctx context.Context, companyID int64, a Asset) (int64, error) {
	// 注意：这里不能传 companyID —— 查询不引用它，PG 无法推断未使用占位符的类型。
	var q string
	var args []any
	args = append(args, a.Type) // $1 = type
	switch a.Type {
	case "root_domain":
		q = `SELECT id FROM assets WHERE type=$1 AND domain=$2`
		args = append(args, a.Domain)
	case "ip":
		q = `SELECT id FROM assets WHERE type=$1 AND ip=$2`
		args = append(args, a.IP)
	case "subdomain":
		q = `SELECT id FROM assets WHERE type=$1 AND domain=$2 AND record_type=$3`
		args = append(args, a.Domain, a.RecordType)
	case "app":
		q = `SELECT id FROM assets WHERE type=$1 AND (app_name=$2 OR bundle_id=$3)`
		args = append(args, a.AppName, a.BundleID)
	case "service":
		q = `SELECT id FROM assets WHERE type=$1 AND url=$2`
		args = append(args, a.URL)
	case "endpoint":
		q = `SELECT id FROM assets WHERE type=$1 AND url=$2 AND method=$3`
		args = append(args, a.URL, a.Method)
	default:
		return 0, fmt.Errorf("unknown asset type %q", a.Type)
	}
	var id int64
	err := d.pool.QueryRow(ctx, q, args...).Scan(&id)
	return id, err
}

// SearchAssets 支持按公司 / 类型 / 关键字过滤 + 分页。返回 (assets, totalCount)
func (d *DB) SearchAssets(ctx context.Context, companyID *int64, typ, q string, limit, offset int) ([]Asset, int, error) {
	where := `WHERE TRUE`
	var args []any
	if companyID != nil {
		args = append(args, *companyID)
		where += fmt.Sprintf(" AND company_id=$%d", len(args))
	}
	if typ != "" {
		args = append(args, typ)
		where += fmt.Sprintf(" AND type=$%d", len(args))
	}
	if q != "" {
		args = append(args, "%"+q+"%")
		where += fmt.Sprintf(` AND (domain ILIKE $%d OR ip ILIKE $%d OR url ILIKE $%d OR app_name ILIKE $%d OR title ILIKE $%d)`,
			len(args), len(args), len(args), len(args), len(args))
	}
	if limit <= 0 {
		limit = 100
	}
	if offset < 0 {
		offset = 0
	}

	// 总数
	var total int
	countQ := `SELECT COUNT(*) FROM assets ` + where
	if err := d.pool.QueryRow(ctx, countQ, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	// 分页数据
	sql := `SELECT id, company_id, type,
		COALESCE(root_domain,'') AS root_domain, COALESCE(domain,'') AS domain,
		COALESCE(record_type,'') AS record_type, COALESCE(ip,'') AS ip,
		COALESCE(app_name,'') AS app_name, COALESCE(bundle_id,'') AS bundle_id,
		COALESCE(url,'') AS url, COALESCE(method,'') AS method,
		COALESCE(title,'') AS title, COALESCE(extra,'{}') AS extra
		FROM assets ` + where + fmt.Sprintf(" ORDER BY id DESC LIMIT $%d OFFSET $%d", len(args)+1, len(args)+2)
	args = append(args, limit, offset)

	rows, err := d.pool.Query(ctx, sql, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []Asset
	for rows.Next() {
		var a Asset
		if err := rows.Scan(&a.ID, &a.CompanyID, &a.Type, &a.RootDomain, &a.Domain, &a.RecordType,
			&a.IP, &a.AppName, &a.BundleID, &a.URL, &a.Method, &a.Title, &a.Extra); err != nil {
			return nil, 0, err
		}
		out = append(out, a)
	}
	return out, total, rows.Err()
}

func (d *DB) GetAsset(ctx context.Context, id int64) (*Asset, error) {
	var a Asset
	err := d.pool.QueryRow(ctx,
		`SELECT id, company_id, type,
			COALESCE(root_domain,'') AS root_domain, COALESCE(domain,'') AS domain,
			COALESCE(record_type,'') AS record_type, COALESCE(ip,'') AS ip,
			COALESCE(app_name,'') AS app_name, COALESCE(bundle_id,'') AS bundle_id,
			COALESCE(url,'') AS url, COALESCE(method,'') AS method,
			COALESCE(title,'') AS title, COALESCE(extra,'{}') AS extra
		 FROM assets WHERE id=$1`, id).
		Scan(&a.ID, &a.CompanyID, &a.Type, &a.RootDomain, &a.Domain, &a.RecordType,
			&a.IP, &a.AppName, &a.BundleID, &a.URL, &a.Method, &a.Title, &a.Extra)
	if err != nil {
		return nil, err
	}
	return &a, nil
}