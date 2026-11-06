# PENTIGENT · AI 渗透测试系统（MVP）

复刻 PENTIGENT 核心架构的 AI 渗透测试系统 MVP：**双图（资产图 + 探索图）+ planner/worker 事件驱动闭环**。

给一个任务目标和描述，系统自己决定"先干什么、再干什么"，用真实工具（bash / HTTP）探测目标资产，
把发现写回数据库，直到证明目标达成或没有新方向收敛。

> 安全声明：本项目仅用于**已授权的渗透测试**。所有工具调用经过审批门（guard），
> 并且 bash/webfetch 的目标必须在任务授权边界（task_scope）内，越权目标由代码硬判拒绝。

---

## 1. 技术栈

| 层 | 选型 |
|---|---|
| 后端 | Go（单二进制） |
| 前端 | Next.js 16 静态导出（go:embed 内嵌） |
| 数据库 | PostgreSQL 16 |
| LLM | OpenAI 兼容接口（官方 / DeepSeek / 通义 / Kimi），内置 mock 无 key 模式 |
| 审批 | 内置规则引擎（allow / deny / ask）+ 资产硬边界 |

## 2. 快速开始

### 2.1 环境依赖

- Go 1.26+（本项目在 go1.27.2 验证）
- PostgreSQL 16（本项目用安装版，DSN 默认 `postgres://postgres:postgres@127.0.0.1:5432/PENTIGENT?sslmode=disable`）
- Node.js 20+（仅构建前端时需；产线只用编译出的单二进制）

### 2.2 一键启动（Windows）

```powershell
# 1) 建库 + 起服务（mock LLM，无需 API key，直接跑通全闭环）
.\run.ps1

# 2) 在线实测（自动创建任务 → 启动 → 轮询 → 校验结果）
.\e2e-test.ps1
```

打开浏览器访问 http://127.0.0.1:8080
- 仓库默认 `config.json` 使用 `default-mock`（无需 key）+ `auth.disabled=true`（本地演示）。
- 若打开鉴权（`auth.disabled=false` 且已替换 `jwt_secret`），首次访问会自动跳到 `/login` 设置管理员密码。
- 命令行/CI 仍可用 `Authorization: Bearer <token>` 调 API；浏览器登录后会同时写入 HttpOnly cookie。

### 2.3 手动构建

```powershell
# 前端（只在 web/ 源码变化时）
cd web
npm install
npm run build
cd ..

# 后端单二进制（自动嵌入前端 dist）
go build -o PENTIGENT.exe ./cmd/PENTIGENT

# 启动
.\PENTIGENT.exe config.json
```

### 2.4 接入真实 LLM

```powershell
# config.json: "llm": { "profile": "openai" }  (任意非 default-mock 名字即启用真实 provider)
$env:OPENAI_API_KEY = "sk-xxx"
$env:OPENAI_BASE_URL = "https://api.openai.com/v1"   # 或 DeepSeek/通义/Kimi 兼容端点
$env:OPENAI_MODEL = "gpt-4o-mini"
.\PENTIGENT.exe config.json

# 启动后先做连通性自检（真实 key 才有意义）
curl -X POST http://127.0.0.1:8080/api/llm/test
```

**真实 LLM 上线检查清单**（mock 的 `add_intent` 序列是写死的，真实模型行为完全不同）：
1. `POST /api/llm/test` 返回 200 → key/端点/模型连通
2. 用**已授权靶场**（如本地 DVWA / HackTheBox Practice）建任务，scope 只填该靶机
3. 观察探索图：planner 是否基于事实派**合理的下一跳**，而非乱派或立刻 prove_goal
4. 确认 guard 越权请求确实被拒（资产硬边界），证明模型没有被诱导越界
5. token 消耗对照 mock（真实模型每次唤醒都读 todolist，in/out 会显著高于 mock）

---

## 3. 核心架构

```
┌──────────── 前端 Next.js（go:embed 内嵌）────────────┐
│  任务列表 · 任务详情(会话/工具调用/探索图) · 资产 · 发现 · 审批  │
└─────────────────────────┬──────────────────────────┘
                          │ HTTP (REST /api/*) + SSE
┌─────────────────────────▼──────────────────────────┐
│ server（net/http）                                    │
│  · Engine：事件驱动闭环（planner + N workers）          │
│  · Guard：工具审批门（规则 + 资产硬边界）                │
└─────────────────────────┬──────────────────────────┘
                          │
┌─────────────────────────▼──────────────────────────┐
│ agent（LLM agent）                                   │
│  · goals 目标分解 + 约束提取                           │
│  · planner 规划者（唯一意图生成者 + todolist）          │
│  · worker 执行者 ×N（领意图 → 工具 → 写回 → 停）        │
└─────────────────────────┬──────────────────────────┘
                          │
┌─────────────────────────▼──────────────────────────┐
│ db（pgx → PostgreSQL）                                │
│  · 资产图：companies / assets / company_scope        │
│  · 探索图：explorations / nodes / edges / anchors     │
│  · 任务层：tasks / task_scope / findings / activity   │
│  · 审批：intercept_rules / intercept_pending          │
└──────────────────────────────────────────────────────┘
```

### 双图

- **资产图**（全局共享真值库）：`root_domain → subdomain → service → endpoint`，`ip` 独立分支。
  父子关系与去重 key 全部由程序计算，agent 只提交原始信息。唯一索引去重。
- **探索图**（每任务独立推进链）：`goal / intent / fact / finding / hint` 节点，
  边 `spawns / derived_from / yields / proves`。
- **锚点** `exploration_anchors(node_id, asset_id)` 连接两图：支持按资产反查测试覆盖。

### 引擎闭环

```
图变更 → debounce(500ms) → 唤醒 planner
  → planner 读探索图态势 + 共享 todolist
  → 判断目标已达成（prove_goal）或派 0..N 条 intent 进 frontier
  → N 个 worker 并发 claimNext 领一条 intent（FOR UPDATE SKIP LOCKED）
  → 真实工具执行（bash/HTTP，先过 guard）
  → 写回 fact / asset / finding + activity 账本
  → 再次触发图变更 → 闭环
```

两个关键设计（照搬 PENTIGENT）：
1. **planner 跨唤醒共享 todolist**（`explorations.todolist` JSONB）
2. **worker 间过程级信息交换**：`search_all_worker_traces` / `get_worker_trace`

## 4. LLM 工具集

| 工具 | 归属 | 作用 |
|---|---|---|
| set_goals / add_task_scope / set_constraints | goals | 目标分解、登记边界与约束 |
| add_intent | planner | 派意图进 frontier（唯一生成者） |
| prove_goal | planner | 声明目标达成 |
| claim_intent | engine | worker 领意图（引擎侧，非 LLM 工具） |
| insert_assets / record_fact / report_finding | worker | 写资产 / 事实 / 漏洞 |
| bash / webfetch | worker | 真实执行（过 guard + 留痕） |
| search_all_worker_traces / get_worker_trace | worker | 过程级信息交换 |

## 5. 审批门（guard）

```
工具调用 → deny 规则(命中即拒) → 资产硬边界(bash/webfetch 目标必须在 scope)
         → 操作员约束 → ask 规则(进待审队列) → allow 规则 → 默认放行
```

- 规则：`match_target=tool_name/tool_input` × `match_type=string/regex` × `action=allow/deny/ask`
  - `tool_name` 规则对所有工具生效；`tool_input` 规则只对执行类工具（`bash`/`webfetch`）生效，
    避免把命令模式套到资产/事实/漏洞的文本数据上（否则记录"含 `rm -rf` 的 RCE 漏洞"会被误拒）
- **资产硬边界**：bash/webfetch 参数里解析出的 host/url 不在任务范围 → 直接 deny（代码硬判）
- **本机/回环地址**不再被单独硬禁：与普通目标一样由 `task_scope` 裁决，因此可授权本地靶场（如 DVWA）
- **重定向**：webfetch 每次 302 都会重新过 guard；bash 里 `curl -L/--location` 因无法预判跳转目标而 fail-closed 拒绝
- 操作员 `allow` 约束命中时可跳过 ask 规则（仍不能绕过 deny 规则/硬边界）
- **授权范围白名单**：goals LLM 无权扩大 `task_scope`，越权条目直接丢弃并记审计日志（`server/scope_policy.go`）
- 内置规则含：`rm -rf` / `mkfs` / `/etc/shadow` / 云元数据 169.254.169.254 等，另有 Windows 破坏性命令（递归删除/格式化/注册表写删/关机/卷影删除/编码命令）见迁移 `0002_guard_hardening.sql`

## 6. API

```
POST   /api/auth/setup         首次设置管理员密码
POST   /api/auth/login         JWT 登录
GET    /api/tasks              任务列表（含 token 消耗/发现数/资产数）
POST   /api/tasks              创建任务（goal+description+scope）
GET    /api/tasks/:id          任务详情
POST   /api/tasks/:id/start    启动
POST   /api/tasks/:id/pause    暂停（断点续跑：探索标 paused，下次 start 恢复未完成 intent）
POST   /api/tasks/:id/stop     停止
DELETE /api/tasks/:id          删除（级联清理）
GET    /api/tasks/:id/events   SSE 活动流（支持 Last-Event-ID；EventSource 可用 ?token= 兜底鉴权）
GET    /api/tasks/:id/graph    探索图数据
GET    /api/assets             资产图（按类型/公司过滤）
GET    /api/findings           漏洞列表
GET    /api/intercept/pending  待审批队列
POST   /api/intercept/:id/decision   allow/deny
GET    /api/health             健康检查
POST   /api/llm/test           LLM 连通性探测（真实 LLM 上线前自检）

# 列表接口分页参数（assets / findings）
GET    /api/assets?type=&q=&limit=50&offset=0   → { assets, total, limit, offset }
GET    /api/findings?task=&severity=&limit=50&offset=0 → { findings, total, limit, offset }
```

## 7. 前端页面

| 页面 | 路由 | 内容 |
|---|---|---|
| 登录/初始化 | `/login` | 首次设置管理员密码 + 登录（鉴权开启时自动跳转） |
| 仪表盘 | `/` | 任务列表 + 新建 + 启动/停止 |
| 任务详情 | `/tasks/[id]` | 探索图可视化 + SSE 活动流 + 节点详情 |
| 资产 | `/assets` | 资产图列表（类型/关键字过滤） |
| 发现 | `/findings` | 漏洞列表（severity 过滤） |
| 审批 | `/intercept` | 待审批队列 + allow/deny + 规则列表 |

## 8. 目录结构

```
PENTIGENT/
├── cmd/PENTIGENT/main.go         入口
├── config/config.go          配置
├── db/
│   ├── migrations/
│   │   ├── 0001_init.sql     幂等建表基线（go:embed）
│   │   └── 0002_guard_hardening.sql  破坏性命令默认规则加固
│   ├── db.go                 pgx pool
│   ├── assets.go             资产图 store
│   ├── exploration.go        探索图 store
│   ├── tasks.go              任务/活动 store
│   ├── findings.go           漏洞/审批 store
│   └── store_adapter.go      agent.Store 适配
├── agent/
│   ├── provider.go           Provider 接口
│   ├── openai.go             OpenAI 兼容实现
│   ├── mock.go               内置 mock LLM（无 key 全闭环）
│   ├── goals.go             目标分解
│   ├── planner.go           规划者
│   ├── worker.go            执行者 + 工具执行
│   ├── tools.go             工具 schema
│   ├── native.go            bash/webfetch 原生执行
│   └── store.go             Store 接口 + provider 单例
├── server/
│   ├── server.go            路由 + JWT + SSE
│   ├── handlers.go          REST handlers
│   ├── engine.go            事件驱动闭环
│   ├── scope_policy.go      LLM 授权范围白名单（防提示注入扩大 scope）
│   └── agentbridge.go       agent↔engine 桥
├── intercept/
│   ├── guard.go             审批门
│   └── guard_test.go        集成测试
├── web/                     Next.js 前端源码
├── webui/static.go          go:embed dist
├── e2e-test.ps1             在线实测脚本
└── run.ps1                  一键启动
```

## 9. 已验证里程碑

| 阶段 | 验收 | 结果 |
|---|---|---|
| M1 数据层 | schema 20 表幂等可重跑 | ✅ |
| M2 LLM 层 | mock 驱动全闭环 | ✅ |
| M3 agent | planner/worker 工具解析 | ✅ |
| M4 引擎 | 闭环收敛 + guard 规则/硬边界 | ✅ |
| M5 API | REST + JWT + SSE 全通 | ✅ |
| M6 前端 | 静态导出内嵌单二进制 | ✅ |
| 集成 | e2e 19 项断言全过（在线 example.com 实测） | ✅ |
| 单元 | agent/db/intercept/server 四包测试全绿 | ✅ |

## 10. 功能完整度（相对 PLAN 的"明确不做"）

| 项 | 状态 |
|---|---|
| 任务级 token 预算 | ⏳ 未做（PLAN 确认后置） |
| 多供应商 failover pool | ⏳ 未做 |
| 流量 MITM 留痕代理 | ⏳ 未做 |
| 漏洞 IM 推送 | ⏳ 未做 |
| 自更新 | ⏳ 未做 |
| ScopeSentry 同步 | ⏳ 未做 |
| 冷归档 / digest 折叠节点 | ⏳ 未做 |
| 前端搜索分页 | ✅ 已做（assets/findings limit+offset+total） |
| LLM 连通性自检 | ✅ 已做（/api/llm/test） |

## 11. 核心机制修复记录

| 机制 | 状态 | 说明 |
|---|---|---|
| planner 跨唤醒 todolist | ✅ 已实现 | 每次唤醒读回并注入提示词；新派动作写回 DB |
| 目标达成校验 | ✅ 已实现 | goal 未全 met 时收敛标 `incomplete`，不误报 done |
| intent 超时回收 | ✅ 已实现 | `ReclaimStuckIntents` 回收崩溃 worker 留下的 running |
| worker 心跳续约 | ✅ 已实现 | worker 每轮刷新 `claimed_at`，长意图不再被误回收重领 |
| ask 审批重试 | ✅ 已实现 | worker 有界轮询人工裁决（默认 120s），放行则继续执行 |
| pause 断点续跑 | ✅ 已实现 | 暂停保留探索，下次 start 恢复未完成 intent；`Stop` 等待 goroutine 退出，暂停后立即启动不再误报 |
| 日志落文件 | ✅ 已实现 | `logging` 包按大小轮转（默认 logs/PENTIGENT.log） |
| 资产公司归属 | ✅ 已实现 | 从 task 查真实 company_id，不再硬编码 |
| 请求体大小上限 | ✅ 已实现 | router 入口 `MaxBytesReader` 1 MiB |
| 口令存储 | ✅ 已实现 | bcrypt（随机盐），不再用 SHA-256 |
| JWT 算法校验 | ✅ 已实现 | 显式限定 HS256；启用鉴权时默认 secret 拒绝启动 |
| SSE 断线续传 | ✅ 已实现 | 服务端写 `id:`，读取 `Last-Event-ID`，前端断线重连带 `lastEventId` 补推 |
| 浏览器鉴权链路 | ✅ 已实现 | 登录写 HttpOnly cookie；SSE/报告导出带鉴权 |
| 重定向越权防护 | ✅ 已实现 | webfetch 每次 302 重新过 guard；bash curl -L fail-closed |

### 安全与可靠性加固（0002 迁移 + 引擎侧）

| 项 | 说明 |
|---|---|
| 授权范围白名单收敛 | goals LLM 提出的 `add_task_scope` 只接受落在"操作员登记范围 ∪ 任务描述主机"内的条目，越权条目丢弃并记审计日志——提示注入无法扩大 `task_scope` |
| LLM 约束只收 deny | goals LLM 提出的 allow 约束被忽略（allow 会跳过 ask 审批，等于让 LLM 削弱审批门） |
| 本地探测误判修复 | `selfProbeDenied` 只拦"本地路径形态"的敏感文件访问；授权目标 URL 路径上的 `/.env`、`/config.json` 等常规检查点不再被误拒；`mkdir` 不再被 "dir " 子串误伤 |
| Windows 破坏性命令默认拒绝 | 新增迁移 `0002_guard_hardening.sql`：递归/强制删除、格式化/清盘、注册表写删、关机重启、卷影删除、远程脚本下载执行、编码命令、清历史 |
| CORS 收紧 | 移除 `Access-Control-Allow-Origin: *`（API 支持同源 cookie 鉴权，通配符会被第三方脚本滥用），只回显同源 origin |
| 未知 API 返回 JSON 404 | 未匹配的 `/api/*` 不再兜底到 SPA 的 HTML，返回 JSON 404 |
| ListPending 参数位号修复 | `status` 为空时 SQL 参数位错（`$2` 只有 1 个参数）导致的查询失败已修复 |
| GetPending 时间戳扫描 | `created_at::text` 与全库写法一致，人工审批轮询不再依赖驱动隐式转换 |
| 停止时状态可持久化 | 引擎收尾改用独立超时上下文（原 ctx 已取消，状态写不进去）；`paused` 不被 `stopped` 覆盖 |
| 僵尸探索恢复 | 修复 `findResumable` 中恒为 false 的判断：进程崩溃遗留的 `running` 探索现在会真正断点续跑，而不是新建探索、遗弃旧意图 |
| 任务运行时长上限 | 新增 `agent.max_runtime_sec`（默认 1800s）：超时标记 `incomplete` 并强制收尾，防工具/LLM 卡死无限运行 |
| 审批裁决幂等 | 只允许裁决 `pending` 记录；已裁决/过期记录返回 404，避免"补批"显示成功但无效果 |
| 前端 SSE 补推 | 断线重连携带 `lastEventId`，不再丢失断线窗口内的事件；并显示"重连中"状态 |
| 前端体验修复 | 导航高亮在 `trailingSlash` 下恢复；资产页补加载/错误态；资产表修复无 key Fragment 警告；导出/保存备注/删规则补错误提示与二次确认；漏洞页导出按钮归位到工具栏 |
| 审批规则默认启用 | 修复 UI 新建规则因 `enabled` 零值而"创建即禁用、静默失效"的问题；写入前校验 match_target/match_type/action 并编译正则，坏正则不再静默存库 |
| 指令规则作用域 | `tool_input` 规则与操作员约束只作用于 `bash/webfetch`；写图工具（资产/事实/漏洞）的文本数据不再被命令黑名单误拒（如漏洞标题含 `rm -rf`） |
| IPv6 纳入硬边界 | 提取/规范化 IPv6（`[::1]:8080`、`0:0:0:0:0:0:0:1` 等），此前 `http://[::1]/` 会因抓不到 host 而绕过范围校验；任务描述里的 IPv6 也能推断进 scope |
| 报告按任务收敛 | 任务报告/覆盖度改走"探索锚点"只取本任务资产，不再把全局资产库其它任务的资产混进报告 |
| 资产入库范围校验 | `insert_assets` 逐资产校验 host 是否在授权范围内（`Guard.ScopeAllows`），范围外资产不入库：资产图是全局真值库，否则等于让 LLM 越权建档并污染其它任务 |

## 12. 与 PENTIGENT 的差异（有意简化）

| 维度 | PENTIGENT | 本 MVP |
|---|---|---|
| 状态并发 | 多 goroutine + sync.Map | 单 goroutine actor / 简单锁 |
| LLM | 双格式 + failover pool + 熔断 | 一个 interface + OpenAI 实现 |
| 上下文 | 每轮全量图 + 复杂压缩 | 增量 delta + 固定窗口 |
| token 预算 / 流量代理 / 通知 | 有 | 后置，MVP 不做 |

## 13. 风险与对策

| 风险 | 对策 |
|---|---|
| LLM 烧钱 | frontier 空就不调 LLM + 上下文固定窗口 + 意图/token 预算 |
| agent 跑偏/死循环 | 单意图 LLM 轮次上限（默认 12）+ 任务时长上限（默认 30 分钟）+ 审批门兜底 |
| 授权范围被 LLM 扩大 | `scope_policy.go` 白名单收敛：只有操作员提供/任务描述中的主机可写入 scope |
| 资产数据脏 | 唯一索引去重 + 程序算父子关系 + 入库前校验 |
| 越权探测 | 资产硬边界代码硬判（不依赖提示词） |
| 无 LLM key | mock provider 先跑通全流程，配 key 即切真实 |