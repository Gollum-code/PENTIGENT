"use client";
import Link from "next/link";
import { useEffect, useState } from "react";
import { api, apiSafe, useToast } from "@/lib/store";
import Nav from "@/components/Nav";

const sevLabel: any = {
  critical: "严重",
  high: "高危",
  medium: "中危",
  low: "低危",
  info: "信息",
};

function SeverityTag({ sev }: { sev: string }) {
  const color =
    sev === "critical" || sev === "high" ? "#ff7b72" : sev === "medium" ? "#ffa657" : sev === "low" ? "#3fb950" : "#8b949e";
  return (
    <span className="tag" style={{ background: "#21262d", color }}>
      {sevLabel[sev] || sev}
    </span>
  );
}

export default function FindingDetail({ id }: { id: string }) {
  const [f, setF] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const toast = useToast();

  useEffect(() => {
    api(`/api/findings/${id}`)
      .then(setF)
      .catch((e) => toast.show(e.message || "加载失败"))
      .finally(() => setLoading(false));
  }, [id]);

  const setStatus = async (status: string) => {
    const d = await apiSafe(`/api/findings/${id}/status`, {
      method: "POST",
      body: JSON.stringify({ status }),
    }, status === "confirmed" ? "已标记为确认" : "已标记为误报");
    if (d) setF((prev: any) => ({ ...prev, status }));
  };

  const remove = async () => {
    if (!confirm("确定删除该漏洞记录？")) return;
    const d = await apiSafe(`/api/findings/${id}`, { method: "DELETE" }, "漏洞已删除");
    if (d) setTimeout(() => (window.location.href = "/findings/"), 600);
  };

  if (loading) {
    return (
      <div className="app">
        <Nav />
        <p className="muted">加载中…</p>
      </div>
    );
  }
  if (!f) {
    return (
      <div className="app">
        <Nav />
        <p className="muted">漏洞不存在或已被删除</p>
      </div>
    );
  }

  const ev = f.evidence || {};

  return (
    <div className="app">
      <Nav />
      <h1>漏洞详情 #{f.id}</h1>

      <div className="card">
        <div className="status-row">
          <h2 style={{ flex: 1 }}>{f.title}</h2>
          <SeverityTag sev={f.severity} />
          <span className="tag gray">{f.status === "confirmed" ? "已确认" : "误报"}</span>
        </div>
        <p className="muted">
          所属项目：{f.task_id ? (
            <Link href={`/tasks/${f.task_id}`}>{f.task_name || `任务 #${f.task_id}`}</Link>
          ) : "—"}
        </p>
        <p className="muted">发现时间：{f.created_at}</p>
        <div className="status-row" style={{ marginTop: 10 }}>
          {f.status === "confirmed" ? (
            <button className="btn ghost" onClick={() => setStatus("dismissed")}>
              标记为误报
            </button>
          ) : (
            <button className="btn" onClick={() => setStatus("confirmed")}>
              重新确认为真
            </button>
          )}
          <button className="btn danger" onClick={remove}>
            删除
          </button>
        </div>
      </div>

      <div className="card">
        <h2>证据链</h2>
        <table>
          <tbody>
            <tr>
              <td style={{ width: 120, color: "#8b949e" }}>漏洞位置</td>
              <td>
                {ev.url ? (
                  <a href={String(ev.url)} target="_blank" rel="noreferrer">
                    {String(ev.url)}
                  </a>
                ) : (
                  "—"
                )}
              </td>
            </tr>
            {Object.entries(ev)
              .filter(([k]) => k !== "url")
              .map(([k, v]) => (
                <tr key={k}>
                  <td style={{ color: "#8b949e" }}>{k}</td>
                  <td>{typeof v === "object" ? JSON.stringify(v) : String(v)}</td>
                </tr>
              ))}
            {Object.keys(ev).length === 0 && (
              <tr>
                <td colSpan={2} className="muted">
                  暂无结构化证据
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      <div className="card">
        <h2>溯源</h2>
        <table>
          <tbody>
            <tr>
              <td style={{ width: 120, color: "#8b949e" }}>关联资产</td>
              <td>
                {f.asset ? (
                  <>
                    <span className="tag">{f.asset.type}</span>{" "}
                    {f.asset.domain || f.asset.url}
                    {f.asset.url && f.asset.domain ? ` (${f.asset.url})` : ""}
                  </>
                ) : (
                  "—"
                )}
              </td>
            </tr>
            <tr>
              <td style={{ color: "#8b949e" }}>发现意图</td>
              <td>{f.intent_title || "—"}</td>
            </tr>
            <tr>
              <td style={{ color: "#8b949e" }}>所属运行</td>
              <td>{f.exploration_id ? `探索 #${f.exploration_id}` : "—"}</td>
            </tr>
          </tbody>
        </table>
      </div>

      <div className="card">
        <Link href="/findings/" className="muted">
          ← 返回漏洞列表
        </Link>
      </div>
    </div>
  );
}