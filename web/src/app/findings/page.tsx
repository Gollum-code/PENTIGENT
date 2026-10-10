"use client";
import Link from "next/link";
import { useEffect, useState } from "react";
import { apiSafe } from "@/lib/store";
import Nav from "@/components/Nav";
import Pagination from "@/components/Pagination";

const sevCls: any = {
  critical: "sev-critical",
  high: "sev-high",
  medium: "sev-medium",
  low: "sev-low",
  info: "sev-info",
};
const PAGE_SIZE = 20;

export default function Findings() {
  const [findings, setFindings] = useState<any[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [sev, setSev] = useState("");
  const [status, setStatus] = useState("");

  const load = async (p = page) => {
    const params = new URLSearchParams();
    if (sev) params.set("severity", sev);
    if (status) params.set("status", status);
    params.set("limit", String(PAGE_SIZE));
    params.set("offset", String((p - 1) * PAGE_SIZE));
    const d = await apiSafe(`/api/findings?${params.toString()}`);
    if (d) {
      setFindings(d.findings || []);
      setTotal(d.total ?? (d.findings || []).length);
    }
  };

  useEffect(() => {
    setPage(1);
  }, [sev, status]);

  useEffect(() => {
    load(page);
  }, [page, sev, status]);

  const toggleStatus = async (f: any) => {
    const next = f.status === "dismissed" ? "confirmed" : "dismissed";
    const d = await apiSafe(`/api/findings/${f.id}/status`, {
      method: "POST",
      body: JSON.stringify({ status: next }),
    }, next === "dismissed" ? "已标记为误报" : "已标记为确认");
    if (d) load(page);
  };

  const remove = async (f: any) => {
    const d = await apiSafe(`/api/findings/${f.id}`, { method: "DELETE" }, "漏洞记录已删除");
    if (d) load(page);
  };

  return (
    <div className="app">
      <Nav />
      <h1>漏洞发现</h1>
      <div className="card">
        <div className="status-row">
          <select style={{ width: 150 }} value={sev} onChange={(e) => setSev(e.target.value)}>
            <option value="">全部级别</option>
            <option value="critical">critical</option>
            <option value="high">high</option>
            <option value="medium">medium</option>
            <option value="low">low</option>
            <option value="info">info</option>
          </select>
          <select style={{ width: 140 }} value={status} onChange={(e) => setStatus(e.target.value)}>
            <option value="">全部状态</option>
            <option value="confirmed">已确认</option>
            <option value="dismissed">误报</option>
          </select>
        </div>
        <table style={{ marginTop: 12 }}>
          <thead>
            <tr>
              <th>ID</th>
              <th>项目</th>
              <th>严重性</th>
              <th>状态</th>
              <th>标题</th>
              <th>操作</th>
            </tr>
          </thead>
          <tbody>
            {findings.map((f) => (
              <tr key={f.id}>
                <td>{f.id}</td>
                <td>
                  <Link href={`/tasks/${f.task_id}`} className="muted">
                    {f.task_name || `任务 #${f.task_id}`}
                  </Link>
                </td>
                <td>
                  <span className={`tag ${sevCls[f.severity]}`}>{f.severity}</span>
                </td>
                <td>
                  <span className={`tag ${f.status === "confirmed" ? "green" : "gray"}`}>
                    {f.status === "confirmed" ? "已确认" : "误报"}
                  </span>
                </td>
                <td>{f.title}</td>
                <td>
                  <button className="btn ghost" onClick={() => toggleStatus(f)}>
                    {f.status === "dismissed" ? "重新确认" : "标记误报"}
                  </button>
                  <button className="btn danger" onClick={() => remove(f)}>
                    删除
                  </button>
                </td>
              </tr>
            ))}
            {findings.length === 0 && (
              <tr>
                <td colSpan={6} className="muted">
                  暂无漏洞发现
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