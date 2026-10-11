-- AI 渗透测试系统 · 幂等 schema
-- 全部 IF NOT EXISTS：启动时重跑 = "重启即迁移"

-- ============================================================================
-- A 资产层（全局共享 · 真值库）
-- ============================================================================

CREATE TABLE IF NOT EXISTS companies (
    id          BIGSERIAL PRIMARY KEY,
    name        TEXT NOT NULL UNIQUE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS assets (
    id           BIGSERIAL PRIMARY KEY,
    company_id   BIGINT REFERENCES companies(id) ON DELETE CASCADE,
    type         TEXT NOT NULL,
    root_domain  TEXT,
    domain       TEXT,
    record_type  TEXT,
    ip           TEXT,
    app_name     TEXT,
    bundle_id    TEXT,
    url          TEXT,
    method       TEXT,
    title        TEXT,
    extra        JSONB NOT NULL DEFAULT '{}'::jsonb,
    discovered_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- 去重索引：每种资产类型独立唯一约束
CREATE UNIQUE INDEX IF NOT EXISTS ux_assets_root_domain ON assets(domain) WHERE type = 'root_domain';
CREATE UNIQUE INDEX IF NOT EXISTS ux_assets_ip          ON assets(ip) WHERE type = 'ip';
CREATE UNIQUE INDEX IF NOT EXISTS ux_assets_subdomain   ON assets(domain, record_type) WHERE type = 'subdomain';
CREATE UNIQUE INDEX IF NOT EXISTS ux_assets_app_name    ON assets(app_name) WHERE type = 'app' AND app_name IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS ux_assets_bundle      ON assets(bundle_id) WHERE type = 'app' AND bundle_id IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS ux_assets_service     ON assets(url) WHERE type = 'service';
CREATE UNIQUE INDEX IF NOT EXISTS ux_assets_endpoint    ON assets(url, method) WHERE type = 'endpoint';

CREATE INDEX IF NOT EXISTS ix_assets_company ON assets(company_id);
CREATE INDEX IF NOT EXISTS ix_assets_type    ON assets(type);

CREATE TABLE IF NOT EXISTS company_scope (
    id          BIGSERIAL PRIMARY KEY,
    company_id  BIGINT NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
    pattern     TEXT NOT NULL,
    kind        TEXT NOT NULL DEFAULT 'domain',   -- domain | ip | url_prefix
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (company_id, pattern, kind)
);

-- ============================================================================
-- B 探索层（每任务独立 · 推进链）
-- ============================================================================

CREATE TABLE IF NOT EXISTS explorations (
    id          BIGSERIAL PRIMARY KEY,
    task_id     BIGINT,
    goal        TEXT NOT NULL,
    status      TEXT NOT NULL DEFAULT 'running',   -- running | done | stopped
    todolist    JSONB NOT NULL DEFAULT '[]'::jsonb,  -- planner 跨唤醒共享记忆
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS exploration_nodes (
    id            BIGSERIAL PRIMARY KEY,
    exploration_id BIGINT NOT NULL REFERENCES explorations(id) ON DELETE CASCADE,
    type          TEXT NOT NULL,  -- goal | intent | fact | finding | hint
    status        TEXT NOT NULL,  -- 见 README 状态机
    title         TEXT NOT NULL DEFAULT '',
    content       JSONB NOT NULL DEFAULT '{}'::jsonb,
    worker_id     TEXT,
    claimed_at    TIMESTAMPTZ,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS ix_nodes_exploration ON exploration_nodes(exploration_id, type, status);

CREATE TABLE IF NOT EXISTS exploration_edges (
    id            BIGSERIAL PRIMARY KEY,
    exploration_id BIGINT NOT NULL REFERENCES explorations(id) ON DELETE CASCADE,
    from_node_id  BIGINT NOT NULL REFERENCES exploration_nodes(id) ON DELETE CASCADE,
    to_node_id    BIGINT NOT NULL REFERENCES exploration_nodes(id) ON DELETE CASCADE,
    relation      TEXT NOT NULL,  -- spawns | derived_from | yields | proves
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (from_node_id, to_node_id, relation)
);

CREATE TABLE IF NOT EXISTS exploration_anchors (
    id            BIGSERIAL PRIMARY KEY,
    exploration_id BIGINT NOT NULL REFERENCES explorations(id) ON DELETE CASCADE,
    node_id       BIGINT NOT NULL REFERENCES exploration_nodes(id) ON DELETE CASCADE,
    asset_id      BIGINT NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (node_id, asset_id)
);

CREATE INDEX IF NOT EXISTS ix_anchors_asset ON exploration_anchors(asset_id);

CREATE TABLE IF NOT EXISTS activity (
    id             BIGSERIAL PRIMARY KEY,
    task_id        BIGINT,
    exploration_id BIGINT,
    node_id        BIGINT,
    role           TEXT NOT NULL DEFAULT '',   -- planner | worker | engine
    step           TEXT NOT NULL DEFAULT '',
    tool           TEXT NOT NULL DEFAULT '',
    input          JSONB NOT NULL DEFAULT '{}'::jsonb,
    output         JSONB NOT NULL DEFAULT '{}'::jsonb,
    status         TEXT NOT NULL DEFAULT 'ok', -- ok | error | denied | waiting
    input_tokens   INT NOT NULL DEFAULT 0,
    output_tokens  INT NOT NULL DEFAULT 0,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS ix_activity_task ON activity(task_id, id DESC);

CREATE TABLE IF NOT EXISTS task_constraints (
    id          BIGSERIAL PRIMARY KEY,
    task_id     BIGINT NOT NULL,
    kind        TEXT NOT NULL DEFAULT 'deny',  -- allow | deny
    pattern     TEXT NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (task_id, kind, pattern)
);

-- ============================================================================
-- C 配置
-- ============================================================================

CREATE TABLE IF NOT EXISTS settings (
    key         TEXT PRIMARY KEY,
    value       JSONB NOT NULL,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS llm_profiles (
    id          BIGSERIAL PRIMARY KEY,
    name        TEXT NOT NULL UNIQUE,
    base_url    TEXT NOT NULL,
    model       TEXT NOT NULL,
    api_key_env TEXT NOT NULL DEFAULT 'OPENAI_API_KEY',
    is_mock     BOOLEAN NOT NULL DEFAULT FALSE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ============================================================================
-- D 任务层
-- ============================================================================

CREATE TABLE IF NOT EXISTS tasks (
    id           BIGSERIAL PRIMARY KEY,
    name         TEXT NOT NULL,
    goal         TEXT NOT NULL,
    description  TEXT NOT NULL DEFAULT '',
    company_id   BIGINT REFERENCES companies(id) ON DELETE SET NULL,
    status       TEXT NOT NULL DEFAULT 'created', -- created|running|paused|stopped|done|failed
    error        TEXT NOT NULL DEFAULT '',
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    started_at   TIMESTAMPTZ,
    finished_at  TIMESTAMPTZ
);
ALTER TABLE tasks ADD COLUMN IF NOT EXISTS notes TEXT NOT NULL DEFAULT '';

CREATE INDEX IF NOT EXISTS ix_tasks_status ON tasks(status, id DESC);

CREATE TABLE IF NOT EXISTS task_scope (
    id          BIGSERIAL PRIMARY KEY,
    task_id     BIGINT NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
    pattern     TEXT NOT NULL,   -- domain / ip / url_prefix
    kind        TEXT NOT NULL DEFAULT 'domain',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (task_id, pattern, kind)
);

CREATE TABLE IF NOT EXISTS task_categories (
    id          BIGSERIAL PRIMARY KEY,
    task_id     BIGINT NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
    name        TEXT NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (task_id, name)
);

-- ============================================================================
-- D2 任务模板（预置渗透场景）
-- ============================================================================

CREATE TABLE IF NOT EXISTS task_templates (
    id           BIGSERIAL PRIMARY KEY,
    name         TEXT NOT NULL UNIQUE,
    description  TEXT NOT NULL DEFAULT '',
    goal         TEXT NOT NULL,
    task_desc    TEXT NOT NULL DEFAULT '',
    scope        TEXT NOT NULL DEFAULT '',  -- 逗号分隔的默认 scope
    tags         TEXT NOT NULL DEFAULT '',
    builtin      BOOLEAN NOT NULL DEFAULT FALSE,  -- 内置模板不可删
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS report_settings (
    id                    BIGSERIAL PRIMARY KEY,
    org_name              TEXT NOT NULL DEFAULT '',   -- 公司/团队抬头
    report_title          TEXT NOT NULL DEFAULT '渗透测试报告',
    logo_url              TEXT NOT NULL DEFAULT '',   -- logo 图片 URL
    show_assets           BOOLEAN NOT NULL DEFAULT TRUE,
    show_facts            BOOLEAN NOT NULL DEFAULT FALSE,
    show_coverage         BOOLEAN NOT NULL DEFAULT TRUE,
    min_severity          TEXT NOT NULL DEFAULT 'info',  -- 低于此级别不纳入报告
    confirmed_only        BOOLEAN NOT NULL DEFAULT FALSE, -- 只含已确认漏洞
    footer                TEXT NOT NULL DEFAULT '',
    updated_at            TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- 默认报告设置（单行，id=1）
INSERT INTO report_settings (id) VALUES (1) ON CONFLICT (id) DO NOTHING;

-- 内置任务模板（幂等插入；scope 留空由用户填目标）
INSERT INTO task_templates (name, description, goal, task_desc, scope, tags, builtin) VALUES
('Web 应用渗透',
 '枚举站点资产、识别技术栈、检查常见 Web 漏洞（SQLi/XSS/弱配置/未授权）',
 '对该目标做授权的 Web 应用安全测试：资产面测绘 + 常见 Web 漏洞验证 + 风险定级',
 '仅探测授权范围内的 Web 服务；验证注入/跨站/弱口令/未授权访问等常见漏洞，并输出证据',
 '', 'web,app,owasp', TRUE),
('内网横向探测',
 '子域名与端口发现、服务指纹识别、内网可达性初判',
 '对授权内网目标做资产面测绘：子域名枚举、端口探测、服务指纹识别',
 '仅限授权网段；不做破坏性横向；输出资产清单与服务指纹',
 '', 'network,internal,recon', TRUE),
('API 安全测试',
 '识别接口、测试认证缺失/越权/注入/敏感数据暴露',
 '对该 API 做授权安全测试：接口枚举、认证与授权缺陷、注入与数据暴露验证',
 '仅测试授权 API；不进行高频压测；输出可复现的漏洞证据',
 '', 'api,auth,injection', TRUE),
('口令与认证安全',
 '弱口令/默认口令检测、认证流程安全、登录接口滥用',
 '对该系统的认证机制做授权安全评估：弱口令、默认凭据、认证绕过、暴力破解风险',
 '仅测试授权系统；不做大规模口令喷洒；记录可复现的认证缺陷',
 '', 'auth,password,credential', TRUE)
ON CONFLICT (name) DO NOTHING;

-- ============================================================================
-- E Agent 角色 / 提示词
-- ============================================================================

CREATE TABLE IF NOT EXISTS agents (
    id          BIGSERIAL PRIMARY KEY,
    role        TEXT NOT NULL UNIQUE,  -- main | planner | worker
    name        TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    model       TEXT NOT NULL DEFAULT '',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS agent_prompts (
    id          BIGSERIAL PRIMARY KEY,
    agent_id    BIGINT NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    name        TEXT NOT NULL,
    content     TEXT NOT NULL DEFAULT '',
    version     INT NOT NULL DEFAULT 1,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (agent_id, name, version)
);

-- ============================================================================
-- F 发现
-- ============================================================================

CREATE TABLE IF NOT EXISTS findings (
    id             BIGSERIAL PRIMARY KEY,
    task_id        BIGINT REFERENCES tasks(id) ON DELETE CASCADE,
    exploration_id BIGINT,
    node_id        BIGINT,
    asset_id       BIGINT,
    title          TEXT NOT NULL,
    severity       TEXT NOT NULL DEFAULT 'info', -- info|low|medium|high|critical
    status         TEXT NOT NULL DEFAULT 'confirmed', -- confirmed | dismissed
    evidence       JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS ix_findings_task ON findings(task_id, id DESC);

-- 同任务同标题的漏洞只保留一条（去重）
CREATE UNIQUE INDEX IF NOT EXISTS ux_findings_task_title
    ON findings(task_id, title) WHERE task_id IS NOT NULL;

-- ============================================================================
-- G 审批门
-- ============================================================================

CREATE TABLE IF NOT EXISTS intercept_rules (
    id           BIGSERIAL PRIMARY KEY,
    name         TEXT NOT NULL,
    match_target TEXT NOT NULL DEFAULT 'tool_name', -- tool_name | tool_input
    match_type   TEXT NOT NULL DEFAULT 'string',    -- string | regex
    pattern      TEXT NOT NULL,
    action       TEXT NOT NULL DEFAULT 'allow',     -- allow | deny | ask
    priority     INT NOT NULL DEFAULT 100,
    enabled      BOOLEAN NOT NULL DEFAULT TRUE,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS intercept_pending (
    id          BIGSERIAL PRIMARY KEY,
    task_id     BIGINT REFERENCES tasks(id) ON DELETE CASCADE,
    node_id     BIGINT,
    tool        TEXT NOT NULL,
    input       JSONB NOT NULL DEFAULT '{}'::jsonb,
    rule_id     BIGINT,
    reason      TEXT NOT NULL DEFAULT '',
    status      TEXT NOT NULL DEFAULT 'pending',   -- pending | approved | denied
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    decided_at  TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS ix_pending_status ON intercept_pending(status, id DESC);

CREATE TABLE IF NOT EXISTS asset_intercept_rules (
    id         BIGSERIAL PRIMARY KEY,
    pattern    TEXT NOT NULL UNIQUE,
    action     TEXT NOT NULL DEFAULT 'deny',  -- deny = 硬边界黑名单
    note       TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ============================================================================
-- 默认数据
-- ============================================================================

INSERT INTO agents (role, name, description, model) VALUES
    ('main',   'Main',   '任务协调与入口', ''),
    ('planner', 'Planner', '唯一意图生成者 + todolist 持有者', ''),
    ('worker',  'Worker',  '领意图执行真实工具并写回', '')
ON CONFLICT (role) DO NOTHING;

-- 默认规则幂等重置：先按已知名字清掉旧默认，再插入新默认
DELETE FROM intercept_rules
 WHERE name IN ('ask-raw-http-post','deny-destructive-rm','deny-disk-write','deny-shutdown',
                'deny-credential-dump','deny-cloud-metadata','ask-write-method','allow-safe-recon',
                'allow-safe-webfetch','allow-graph-tools','allow-record-fact','allow-report-finding',
                'allow-trace-search','allow-trace-get');

INSERT INTO intercept_rules (name, match_target, match_type, pattern, action, priority) VALUES
    ('deny-destructive-rm',    'tool_input', 'regex',   '(?i)\brm\s+-[rf]',            'deny',  1),
    ('deny-disk-write',        'tool_input', 'string',  'mkfs',                            'deny',  1),
    ('deny-shutdown',          'tool_input', 'string',  'shutdown',                        'deny',  1),
    ('deny-credential-dump',   'tool_input', 'string',  '/etc/shadow',                     'deny',  1),
    ('deny-cloud-metadata',    'tool_input', 'string',  '169.254.169.254',                 'deny',  1),
    ('ask-write-method',       'tool_input', 'regex',   '(?i)"method"\s*:\s*"(POST|PUT|DELETE|PATCH)"', 'ask', 500),
    ('allow-safe-recon',       'tool_name',  'string',  'bash',                            'allow', 900),
    ('allow-safe-webfetch',    'tool_name',  'string',  'webfetch',                        'allow', 950),
    ('allow-graph-tools',      'tool_name',  'string',  'insert_assets',                   'allow', 950),
    ('allow-record-fact',      'tool_name',  'string',  'record_fact',                     'allow', 950),
    ('allow-report-finding',   'tool_name',  'string',  'report_finding',                  'allow', 950),
    ('allow-trace-search',     'tool_name',  'string',  'search_all_worker_traces',        'allow', 950),
    ('allow-trace-get',        'tool_name',  'string',  'get_worker_trace',                'allow', 950)
ON CONFLICT DO NOTHING;

INSERT INTO asset_intercept_rules (pattern, action, note) VALUES
    ('169.254.169.254', 'deny', '云元数据端点，永不探测'),
    ('metadata.google.internal', 'deny', 'GCP 元数据')
ON CONFLICT (pattern) DO NOTHING;

INSERT INTO llm_profiles (name, base_url, model, is_mock) VALUES
    ('default-mock', '', '', TRUE),
    ('default-openai', 'https://api.openai.com/v1', 'gpt-4o-mini', FALSE)
ON CONFLICT (name) DO NOTHING;