"use client";
import { useEffect, useState } from "react";
import { apiSafe } from "@/lib/store";
import Nav from "@/components/Nav";

export default function Settings() {
  const [s, setS] = useState<any>(null);
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    apiSafe("/api/report-settings")
      .then((d) => d && setS(d))
      .catch(() => {});
  }, []);

  const set = (k: string, v: any) => setS((p: any) => ({ ...p, [k]: v }));

  const save = async () => {
    setSaving(true);
    const d = await apiSafe("/api/report-settings", {
      method: "POST",
      body: JSON.stringify(s),
    }, "报告设置已保存");
    if (d) setS(d);
    setSaving(false);
  };

  if (!s) {
    return (
      <div className="app">
        <Nav />
        <p className="muted">加载中…</p>
      </div>
    );
  }

  return (
    <div className="app">
      <Nav />
      <h1>报告设置</h1>
      <div className="card">
        <h2>品牌抬头</h2>
        <label>公司 / 团队名称</label>
        <input value={s.org_name || ""} onChange={(e) => set("org_name", e.target.value)} placeholder="如：某某安全实验室" />
        <label>报告标题</label>
        <input value={s.report_title || ""} onChange={(e) => set("report_title", e.target.value)} />
        <label>Logo 图片 URL</label>
        <input value={s.logo_url || ""} onChange={(e) => set("logo_url", e.target.value)} placeholder="https://..." />
        <label>页脚说明</label>
        <input value={s.footer || ""} onChange={(e) => set("footer", e.target.value)} />
      </div>

      <div className="card">
        <h2>报告章节</h2>
        <label style={{ display: "flex", alignItems: "center", gap: 8 }}>
          <input type="checkbox" style={{ width: "auto" }} checked={s.show_assets} onChange={(e) => set("show_assets", e.target.checked)} />
          包含资产清单
        </label>
        <label style={{ display: "flex", alignItems: "center", gap: 8 }}>
          <input type="checkbox" style={{ width: "auto" }} checked={s.show_facts} onChange={(e) => set("show_facts", e.target.checked)} />
          包含探测事实
        </label>
        <label style={{ display: "flex", alignItems: "center", gap: 8 }}>
          <input type="checkbox" style={{ width: "auto" }} checked={s.show_coverage} onChange={(e) => set("show_coverage", e.target.checked)} />
          包含资产测试覆盖
        </label>
      </div>

      <div className="card">
        <h2>漏洞过滤</h2>
        <label>最低严重性（低于此级别不写入报告）</label>
        <select style={{ width: 180 }} value={s.min_severity || "info"} onChange={(e) => set("min_severity", e.target.value)}>
          <option value="info">全部（info）</option>
          <option value="low">低危及以上</option>
          <option value="medium">中危及以上</option>
          <option value="high">高危及以上</option>
          <option value="critical">仅严重</option>
        </select>
        <label style={{ display: "flex", alignItems: "center", gap: 8 }}>
          <input type="checkbox" style={{ width: "auto" }} checked={s.confirmed_only} onChange={(e) => set("confirmed_only", e.target.checked)} />
          只包含已确认漏洞（过滤误报）
        </label>
        <div style={{ marginTop: 10 }}>
          <button className="btn" onClick={save} disabled={saving}>
            {saving ? "保存中…" : "保存设置"}
          </button>
        </div>
      </div>
    </div>
  );
}