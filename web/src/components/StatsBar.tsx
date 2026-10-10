"use client";
import { useEffect, useState } from "react";
import { api } from "@/lib/store";

function Card({ label, value, color }: { label: string; value: any; color?: string }) {
  return (
    <div className="card" style={{ margin: 0, padding: 12, minWidth: 100, textAlign: "center" }}>
      <div style={{ fontSize: 22, fontWeight: 700, color: color || "#e6e8eb" }}>{value}</div>
      <div className="muted" style={{ fontSize: 12 }}>{label}</div>
    </div>
  );
}

export default function StatsBar() {
  const [s, setS] = useState<any>(null);

  useEffect(() => {
    const load = () =>
      api("/api/stats")
        .then(setS)
        .catch(() => {});
    load();
    const iv = setInterval(load, 5000);
    return () => clearInterval(iv);
  }, []);

  if (!s) return null;
  const sev = s.findings_by_severity || {};
  const high = (sev.critical || 0) + (sev.high || 0);

  return (
    <div className="status-row" style={{ marginBottom: 12, alignItems: "stretch" }}>
      <Card label="任务总数" value={s.tasks_total} />
      <Card label="运行中" value={s.tasks_running} color="#7ee787" />
      <Card label="已完成" value={s.tasks_done} color="#7ee787" />
      <Card label="资产" value={s.assets_total} color="#58a6ff" />
      <Card label="漏洞总数" value={s.findings_total} color={high > 0 ? "#ffa657" : "#8b949e"} />
      <Card label="高危+严重" value={high} color={high > 0 ? "#ff7b72" : "#8b949e"} />
      <Card label="Token 消耗" value={`${s.tokens_in}/${s.tokens_out}`} color="#d2a8ff" />
    </div>
  );
}