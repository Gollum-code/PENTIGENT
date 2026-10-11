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
首次需要设置管理员密码（或跳过 —— 直接 curl 走 API 也行）。

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
- **资产硬边界**：bash/webfetch 参数里解析出的 host/url 不在任务范围 → 直接 deny（代码硬判）
- 内置规则含：`rm -rf` / `/etc/shadow` / 云元数据 169.254.169.254 等拒绝项

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
GET    /api/tasks/:id/events   SSE 活动流
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
│   ├── schema.sql            幂等建表（go:embed）
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

## 10. 核心机制修复记录

| 机制 | 状态 | 说明 |
|---|---|---|
| planner 跨唤醒 todolist | ✅ 已实现 | 每次唤醒读回并注入提示词；新派动作写回 DB |
| 目标达成校验 | ✅ 已实现 | goal 未全 met 时收敛标 `incomplete`，不误报 done |
| intent 超时回收 | ✅ 已实现 | `ReclaimStuckIntents` 回收崩溃 worker 留下的 running |
| ask 审批重试 | ✅ 已实现 | worker 有界轮询人工裁决（默认 120s），放行则继续执行 |
| pause 断点续跑 | ✅ 已实现 | 暂停保留探索，下次 start 恢复未完成 intent |
| 日志落文件 | ✅ 已实现 | `logging` 包按大小轮转（默认 logs/PENTIGENT.log） |
| 资产公司归属 | ✅ 已实现 | 从 task 查真实 company_id，不再硬编码 |

## 10. 与 PENTIGENT 的差异（有意简化）

| 维度 | PENTIGENT | 本 MVP |
|---|---|---|
| 状态并发 | 多 goroutine + sync.Map | 单 goroutine actor / 简单锁 |
| LLM | 双格式 + failover pool + 熔断 | 一个 interface + OpenAI 实现 |
| 上下文 | 每轮全量图 + 复杂压缩 | 增量 delta + 固定窗口 |
| token 预算 / 流量代理 / 通知 | 有 | 后置，MVP 不做 |

## 11. 风险与对策

| 风险 | 对策 |
|---|---|
| LLM 烧钱 | frontier 空就不调 LLM + 上下文固定窗口 |
| agent 跑偏/死循环 | 迭代上限 60 次强制收尾 + worker 单意图边界 + 审批门兜底 |
| 资产数据脏 | 唯一索引去重 + 程序算父子关系 + 入库前校验 |
| 越权探测 | 资产硬边界代码硬判（不依赖提示词） |
| 无 LLM key | mock provider 先跑通全流程，配 key 即切真实 |