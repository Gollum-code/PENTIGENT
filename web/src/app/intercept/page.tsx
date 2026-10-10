"use client";
import Link from "next/link";
import { useEffect, useState } from "react";
import { apiSafe } from "@/lib/store";
import Nav from "@/components/Nav";

export default function Intercept() {
  const [pending, setPending] = useState<any[]>([]);
  const [rules, setRules] = useState<any[]>([]);
  const [showAll, setShowAll] = useState(false);
  const [showRuleForm, setShowRuleForm] = useState(false);
  const [ruleForm, setRuleForm] = useState({
    name: "",
    match_target: "tool_input",
    match_type: "string",
    pattern: "",
    action: "deny",
    priority: 100,
  });

  const load = async () => {
    const d = await apiSafe(`/api/intercept/pending?status=${showAll ? "" : "pending"}`);
    if (d) setPending(d.pending || []);
    const r = await apiSafe("/api/intercept/rules");
    if (r) setRules(r.rules || []);
  };

  useEffect(() => {
    load();
    const iv = setInterval(load, 3000);
    return () => clearInterval(iv);
  }, [showAll]);

  const decide = async (id: number, approved: boolean) => {
    await apiSafe(`/api/intercept/${id}/decision`, {
      method: "POST",
      body: JSON.stringify({ approved }),
    }, approved ? "已放行" : "已拒绝");
    load();
  };

  const createRule = async () => {
    if (!ruleForm.name || !ruleForm.pattern) {
      return;
    }
    const d = await apiSafe("/api/intercept/rules", {
      method: "POST",
      body: JSON.stringify({ ...ruleForm, priority: Number(ruleForm.priority) }),
    }, "规则已创建");
    if (d) {
      setShowRuleForm(false);
      setRuleForm({ name: "", match_target: "tool_input", match_type: "string", pattern: "", action: "deny", priority: 100 });
      load();
    }
  };

  const deleteRule = async (id: number) => {
    const d = await apiSafe(`/api/intercept/rules/${id}`, { method: "DELETE" }, "规则已删除");
    if (d) load();
  };

  return (
    <div className="app">
      <Nav />
      <h1>审批门（guard / intercept）</h1>
      <div className="card">
        <div className="status-row">
          <h2 style={{ flex: 1 }}>待审批队列（{pending.length}）</h2>
          <button className="btn ghost" onClick={() => setShowAll(!showAll)}>
            {showAll ? "只看待审" : "查看全部"}
          </button>
        </div>
        {pending.map((p) => (
          <div key={p.id} className="act-item">
            <div>
              <span className="t">#{p.id}</span> 工具 <span className="tool">{p.tool}</span>{" "}
              <span className="tag gray">{p.status}</span>
            </div>
            <p className="muted">
              <Link href={`/tasks/${p.task_id}`}>任务：{p.task_name || `#${p.task_id}`}</Link>
              {p.intent_title && <> · 意图：{p.intent_title}</>}
            </p>
            <pre>{JSON.stringify(p.input)}</pre>
            <p className="muted">{p.reason}</p>
            {p.status === "pending" && (
              <span>
                <button className="btn" onClick={() => decide(p.id, true)}>
                  放行
                </button>
                <button className="btn danger" onClick={() => decide(p.id, false)}>
                  拒绝
                </button>
              </span>
            )}
          </div>
        ))}
        {pending.length === 0 && <p className="muted">无待审批项</p>}
      </div>
      <div className="card">
        <div className="status-row">
          <h2 style={{ flex: 1 }}>拦截规则</h2>
          <button className="btn" onClick={() => setShowRuleForm(!showRuleForm)}>
            {showRuleForm ? "取消" : "新增规则"}
          </button>
        </div>
        {showRuleForm && (
          <div className="card" style={{ marginTop: 8, padding: 12 }}>
            <div className="status-row">
              <input style={{ flex: 1, marginBottom: 0 }} placeholder="规则名称" value={ruleForm.name} onChange={(e) => setRuleForm({ ...ruleForm, name: e.target.value })} />
              <select
                style={{ width: 130, marginBottom: 0 }}
                value={ruleForm.action}
                onChange={(e) => setRuleForm({ ...ruleForm, action: e.target.value })}
              >
                <option value="deny">deny</option>
                <option value="ask">ask</option>
                <option value="allow">allow</option>
              </select>
            </div>
            <div className="status-row" style={{ marginTop: 8 }}>
              <select
                style={{ width: 140, marginBottom: 0 }}
                value={ruleForm.match_target}
                onChange={(e) => setRuleForm({ ...ruleForm, match_target: e.target.value })}
              >
                <option value="tool_name">工具名</option>
                <option value="tool_input">工具参数</option>
              </select>
              <select
                style={{ width: 110, marginBottom: 0 }}
                value={ruleForm.match_type}
                onChange={(e) => setRuleForm({ ...ruleForm, match_type: e.target.value })}
              >
                <option value="string">包含</option>
                <option value="regex">正则</option>
              </select>
              <input
                style={{ flex: 1, marginBottom: 0 }}
                placeholder="匹配模式（如：rm -rf 或 169.254.169.254）"
                value={ruleForm.pattern}
                onChange={(e) => setRuleForm({ ...ruleForm, pattern: e.target.value })}
              />
              <button className="btn" onClick={createRule}>创建</button>
            </div>
          </div>
        )}
        <table style={{ marginTop: 8 }}>
          <thead>
            <tr>
              <th>名称</th>
              <th>匹配目标</th>
              <th>模式</th>
              <th>动作</th>
              <th>优先级</th>
              <th>操作</th>
            </tr>
          </thead>
          <tbody>
            {rules.map((r) => (
              <tr key={r.id}>
                <td>{r.name}</td>
                <td className="muted">{r.match_target}</td>
                <td>
                  <code>{r.pattern}</code>
                </td>
                <td>
                  <span className="tag" style={{ background: r.action === "deny" ? "#6e1f20" : r.action === "ask" ? "#6e4411" : "#1f6f34", color: r.action === "deny" ? "#ff7b72" : r.action === "ask" ? "#ffa657" : "#7ee787" }}>
                    {r.action}
                  </span>
                </td>
                <td className="muted">{r.priority}</td>
                <td>
                  <button className="btn danger" onClick={() => deleteRule(r.id)}>删除</button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}