"use client";
import { useEffect, useState } from "react";
import { api } from "@/lib/store";
import Nav from "@/components/Nav";
import Pagination from "@/components/Pagination";

const PAGE_SIZE = 20;

export default function Assets() {
  const [assets, setAssets] = useState<any[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [type, setType] = useState("");
  const [q, setQ] = useState("");
  const [coverage, setCoverage] = useState<Record<number, any>>({});
  const [open, setOpen] = useState<number | null>(null);

  const load = async (p = page) => {
    const params = new URLSearchParams();
    if (type) params.set("type", type);
    if (q) params.set("q", q);
    params.set("limit", String(PAGE_SIZE));
    params.set("offset", String((p - 1) * PAGE_SIZE));
    const d = await api(`/api/assets?${params.toString()}`);
    setAssets(d.assets || []);
    setTotal(d.total ?? (d.assets || []).length);
  };

  // 类型切换回到第一页
  useEffect(() => {
    setPage(1);
  }, [type]);

  useEffect(() => {
    load(page);
  }, [page, type]);

  const search = () => {
    setPage(1);
    load(1);
  };

  const toggleCoverage = async (id: number) => {
    if (open === id) {
      setOpen(null);
      return;
    }
    if (!coverage[id]) {
      try {
        const d = await api(`/api/assets/${id}/coverage`);
        const item = d.coverage?.[0];
        setCoverage((prev) => ({ ...prev, [id]: item }));
      } catch {}
    }
    setOpen(id);
  };

  return (
    <div className="app">
      <Nav />
      <h1>资产图（全局真值库）</h1>
      <div className="card">
        <div className="status-row">
          <select style={{ width: 180 }} value={type} onChange={(e) => setType(e.target.value)}>
            <option value="">全部类型</option>
            <option value="root_domain">root_domain</option>
            <option value="subdomain">subdomain</option>
            <option value="ip">ip</option>
            <option value="service">service</option>
            <option value="endpoint">endpoint</option>
          </select>
          <input
            style={{ width: 240, marginBottom: 0 }}
            placeholder="搜索域名/URL"
            value={q}
            onChange={(e) => setQ(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && search()}
          />
          <button className="btn" onClick={search}>
            搜索
          </button>
        </div>
        <table style={{ marginTop: 12 }}>
          <thead>
            <tr>
              <th>ID</th>
              <th>类型</th>
              <th>域名</th>
              <th>URL</th>
              <th>覆盖</th>
            </tr>
          </thead>
          <tbody>
            {assets.map((a) => {
              const c = coverage[a.id];
              return (
                <>
                  <tr key={a.id}>
                    <td>{a.id}</td>
                    <td>
                      <span className="tag">{a.type}</span>
                    </td>
                    <td>{a.domain}</td>
                    <td>{a.url}</td>
                    <td>
                      <button className="btn ghost" onClick={() => toggleCoverage(a.id)}>
                        {open === a.id ? "收起" : "覆盖"}
                      </button>
                    </td>
                  </tr>
                  {open === a.id && (
                    <tr key={`${a.id}-cov`}>
                      <td colSpan={5}>
                        <div className="act-item">
                          {c ? (
                            <>
                              {c.tested_by?.length > 0 && (
                                <>
                                  <span className="muted">被意图测试：</span>
                                  {c.tested_by.map((n: any) => (
                                    <span key={n.id} className="tag green">#{n.id} {n.title}</span>
                                  ))}
                                </>
                              )}
                              {c.findings?.length > 0 && (
                                <>
                                  <br />
                                  <span className="muted">相关发现：</span>
                                  {c.findings.map((n: any) => (
                                    <span key={n.id} className="tag red">#{n.id} {n.title}</span>
                                  ))}
                                </>
                              )}
                              {!c.tested_by?.length && !c.findings?.length && (
                                <span className="muted">尚未被测试</span>
                              )}
                            </>
                          ) : (
                            <span className="muted">加载中…</span>
                          )}
                        </div>
                      </td>
                    </tr>
                  )}
                </>
              );
            })}
            {assets.length === 0 && (
              <tr>
                <td colSpan={5} className="muted">
                  暂无资产
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