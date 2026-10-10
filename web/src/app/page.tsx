"use client";
import Link from "next/link";
import { useEffect, useState } from "react";
import { api, apiSafe, useAuth } from "@/lib/store";
import Nav from "@/components/Nav";
import Pagination from "@/components/Pagination";
import StatsBar from "@/components/StatsBar";

// 任务状态徽章配色：done=绿 / incomplete=橙 / failed=红 / running=绿闪 / 其他=灰
function statusStyle(status: string): { bg: string; fg: string } {
  switch (status) {
    case "done":
      return { bg: "#1f6f34", fg: "#7ee787" };
    case "incomplete":
      return { bg: "#6e4411", fg: "#ffa657" };
    case "failed":
      return { bg: "#6e1f20", fg: "#ff7b72" };
    case "running":
      return { bg: "#1f6f34", fg: "#7ee787" };
    default:
      return { bg: "#21262d", fg: "#8b949e" };
  }
}

function Dashboard() {
  const [tasks, setTasks] = useState<any[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [statusFilter, setStatusFilter] = useState("");
  const [search, setSearch] = useState("");
  const [showCreate, setShowCreate] = useState(false);
  const [showReset, setShowReset] = useState(false);
  const [form, setForm] = useState({ name: "", goal: "", description: "", scope: "" });
  const { setToken, setSetupNeeded } = useAuth();

  const PAGE_SIZE = 20;
  const load = async (p = page, st = statusFilter, q = search) => {
    try {
      const params = new URLSearchParams();
      if (st) params.set("status", st);
      if (q) params.set("q", q);
      params.set("limit", String(PAGE_SIZE));
      params.set("offset", String((p - 1) * PAGE_SIZE));
      const d = await api(`/api/tasks?${params.toString()}`);
      setTasks(d.tasks || []);
      setTotal(d.total ?? (d.tasks || []).length);
    } catch (e: any) {
      setToken(null);
    }
  };

  useEffect(() => {
    api("/api/health")
      .then((h) => setSetupNeeded(!h.setup))
      .catch(() => {});
    // 自动轮询：任务运行状态/发现数实时更新
    const iv = setInterval(() => load(page, statusFilter, search), 3000);
    return () => clearInterval(iv);
  }, [page, statusFilter, search]);

  // 首次 + 分页/筛选变化
  useEffect(() => {
    load(page, statusFilter, search);
  }, [page, statusFilter, search]);

  const changeFilter = (st: string) => {
    setPage(1);
    setStatusFilter(st);
  };

  const create = async () => {
    const scope = form.scope.split(",").map((s) => s.trim()).filter(Boolean);
    const d = await apiSafe("/api/tasks", {
      method: "POST",
      body: JSON.stringify({ ...form, scope }),
    }, "任务已创建");
    if (d) {
      setShowCreate(false);
      setForm({ name: "", goal: "", description: "", scope: "" });
      load(page, statusFilter, search);
    }
  };

  const start = async (id: number) => {
    const d = await apiSafe(`/api/tasks/${id}/start`, { method: "POST" }, "任务已启动");
    if (d) load(page, statusFilter, search);
  };
  const stop = async (id: number) => {
    const d = await apiSafe(`/api/tasks/${id}/stop`, { method: "POST" }, "任务已停止");
    if (d) load(page, statusFilter, search);
  };
  const clone = async (id: number) => {
    const d = await apiSafe(`/api/tasks/${id}/clone`, { method: "POST" }, "已复制为新任务");
    if (d) load(page, statusFilter, search);
  };
  const remove = async (id: number) => {
    if (!confirm("确定删除该任务及其全部数据？")) return;
    const d = await apiSafe(`/api/tasks/${id}`, { method: "DELETE" }, "任务已删除");
    if (d) load(page, statusFilter, search);
  };
  const resetAll = async () => {
    if (!confirm("清空全部任务/资产/漏洞/活动数据？（规则与配置保留）")) return;
    const d = await apiSafe("/api/reset", {
      method: "POST",
      body: JSON.stringify({ confirm: "RESET" }),
    }, "已清空演示数据");
    if (d) load(1, "", "");
  };

  return (
    <div className="app">
      <Nav />
      <h1>任务仪表盘</h1>
      <StatsBar />
      <button className="btn" onClick={() => setShowCreate(!showCreate)}>
        {showCreate ? "取消" : "新建任务"}
      </button>
      <button className="btn ghost" onClick={() => setShowReset(true)}>
        清空数据
      </button>
      {showReset && (
        <div className="card" style={{ marginTop: 12 }}>
          <h2>清空演示数据</h2>
          <p className="muted">
            将删除全部任务、探索、资产、漏洞、活动记录（审批规则与系统配置保留）。
          </p>
          <button className="btn danger" onClick={async () => { setShowReset(false); await resetAll(); }}>
            确认清空
          </button>
          <button className="btn ghost" onClick={() => setShowReset(false)}>取消</button>
        </div>
      )}
      {showCreate && (
        <div className="card" style={{ marginTop: 12 }}>
          <h2>新建渗透测试任务</h2>
          <label>任务名称</label>
          <input
            value={form.name}
            onChange={(e) => setForm({ ...form, name: e.target.value })}
            placeholder="线上系统实测"
          />
          <label>目标 Goal（必须）</label>
          <input
            value={form.goal}
            onChange={(e) => setForm({ ...form, goal: e.target.value })}
            placeholder="探测 example.com 的资产面并发现 Web 漏洞"
          />
          <label>描述</label>
          <textarea
            rows={3}
            value={form.description}
            onChange={(e) => setForm({ ...form, description: e.target.value })}
            placeholder="授权范围内渗透测试说明"
          />
          <label>授权范围（逗号分隔，硬边界）</label>
          <input
            value={form.scope}
            onChange={(e) => setForm({ ...form, scope: e.target.value })}
            placeholder="example.com, api.example.com"
          />
          <button className="btn" onClick={create}>
            创建并提交
          </button>
        </div>
      )}
      <div className="card" style={{ marginTop: 12 }}>
        <div className="status-row">
          <h2 style={{ flex: 1 }}>任务列表</h2>
          <input
            style={{ width: 200, marginBottom: 0 }}
            placeholder="搜索任务名/目标"
            value={search}
            onChange={(e) => {
              setSearch(e.target.value);
              setPage(1);
            }}
          />
          <select
            style={{ width: 140 }}
            value={statusFilter}
            onChange={(e) => changeFilter(e.target.value)}
          >
            <option value="">全部状态</option>
            <option value="running">运行中</option>
            <option value="done">已完成</option>
            <option value="incomplete">未完成</option>
            <option value="failed">失败</option>
            <option value="paused">已暂停</option>
            <option value="stopped">已停止</option>
            <option value="created">已创建</option>
          </select>
        </div>
        <table style={{ marginTop: 8 }}>
          <thead>
            <tr>
              <th>ID</th>
              <th>名称</th>
              <th>状态</th>
              <th>发现</th>
              <th>资产</th>
              <th>Token in/out</th>
              <th>操作</th>
            </tr>
          </thead>
          <tbody>
            {tasks.map((t) => (
              <tr key={t.id}>
                <td>{t.id}</td>
                <td>
                  <Link href={`/tasks/${t.id}`}>{t.name}</Link>
                </td>
                <td>
                  <span className="dot running" style={{ display: t.status === "running" ? "inline-block" : "none" }} />
                  <span
                    className="tag"
                    style={{
                      background: statusStyle(t.status).bg,
                      color: statusStyle(t.status).fg,
                    }}
                  >
                    {t.status}
                  </span>
                </td>
                <td>{t.findings}</td>
                <td>{t.assets}</td>
                <td className="muted">{t.tokens_in}/{t.tokens_out}</td>
                <td>
                  <button className="btn" onClick={() => start(t.id)} disabled={t.status === "running"}>
                    启动
                  </button>
                  <button className="btn ghost" onClick={() => stop(t.id)} disabled={t.status !== "running"}>
                    停止
                  </button>
                  <button className="btn ghost" onClick={() => clone(t.id)}>
                    复制
                  </button>
                  <button className="btn danger" onClick={() => remove(t.id)}>
                    删除
                  </button>
                </td>
              </tr>
            ))}
            {tasks.length === 0 && (
              <tr>
                <td colSpan={7} className="muted">
                  暂无任务
                </td>
              </tr>
            )}
          </tbody>
        </table>
        <Pagination page={page} pageSize={PAGE_SIZE} total={total} onChange={setPage} />
      </div>
    </div>
  );
}

export default function Page() {
  return <Dashboard />;
}