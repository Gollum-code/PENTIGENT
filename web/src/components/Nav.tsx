"use client";
import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { useEffect, useState } from "react";
import { api } from "@/lib/store";

const links = [
  { href: "/", label: "仪表盘" },
  { href: "/assets", label: "资产" },
  { href: "/findings", label: "发现" },
  { href: "/intercept", label: "审批" },
  { href: "/settings", label: "设置" },
  { href: "/help", label: "帮助" },
];

export default function Nav() {
  const pathname = usePathname();
  const router = useRouter();
  const [q, setQ] = useState("");
  const [results, setResults] = useState<any>({ tasks: [], assets: [], findings: [] });
  const [showResults, setShowResults] = useState(false);

  // 全局搜索：跨 任务/资产/漏洞
  useEffect(() => {
    if (!q.trim()) {
      setResults({ tasks: [], assets: [], findings: [] });
      setShowResults(false);
      return;
    }
    const t = setTimeout(() => {
      api(`/api/search?q=${encodeURIComponent(q)}`)
        .then((d) => {
          setResults(d);
          setShowResults(true);
        })
        .catch(() => {});
    }, 250);
    return () => clearTimeout(t);
  }, [q]);

  const go = (path: string) => {
    setShowResults(false);
    setQ("");
    router.push(path);
  };

  return (
    <nav className="nav">
      <strong style={{ marginRight: 12 }}>PENTIGENT</strong>
      {links.map((l) => (
        <Link key={l.href} href={l.href} className={pathname === l.href ? "active" : ""}>
          {l.label}
        </Link>
      ))}
      <div style={{ flex: 1 }} />
      <div style={{ position: "relative", width: 260 }}>
        <input
          style={{ marginBottom: 0, padding: "4px 10px", fontSize: 13 }}
          placeholder="全局搜索 任务/资产/漏洞"
          value={q}
          onChange={(e) => setQ(e.target.value)}
          onFocus={() => setShowResults(true)}
        />
        {showResults && (
          <div
            style={{
              position: "absolute",
              top: "100%",
              left: 0,
              right: 0,
              background: "#161b22",
              border: "1px solid #30363d",
              borderRadius: 6,
              zIndex: 100,
              maxHeight: 320,
              overflowY: "auto",
            }}
            onMouseLeave={() => setShowResults(false)}
          >
            {results.tasks?.map((t: any) => (
              <div key={`t${t.id}`} style={{ padding: "6px 10px" }}>
                <a onClick={() => go(`/tasks/${t.id}/`)} style={{ cursor: "pointer" }}>
                  <span className="tag green">任务</span> {t.name}
                </a>
              </div>
            ))}
            {results.assets?.map((a: any) => (
              <div key={`a${a.id}`} style={{ padding: "6px 10px" }}>
                <a onClick={() => go("/assets/")} style={{ cursor: "pointer" }}>
                  <span className="tag">资产</span> {a.domain || a.url}
                </a>
              </div>
            ))}
            {results.findings?.map((f: any) => (
              <div key={`f${f.id}`} style={{ padding: "6px 10px" }}>
                <a onClick={() => go(`/findings/${f.id}/`)} style={{ cursor: "pointer" }}>
                  <span className="tag red">漏洞</span> {f.title}
                </a>
              </div>
            ))}
            {results.tasks?.length === 0 && results.assets?.length === 0 && results.findings?.length === 0 && (
              <div className="muted" style={{ padding: "8px 10px" }}>
                无结果
              </div>
            )}
          </div>
        )}
      </div>
    </nav>
  );
}