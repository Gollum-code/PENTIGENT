"use client";
import { useEffect, useRef, useState } from "react";
import { api } from "@/lib/store";
import Nav from "@/components/Nav";

export default function TaskDetail({ id }: { id: string }) {
  const [task, setTask] = useState<any>(null);
  const [graph, setGraph] = useState<any>({ nodes: [], edges: [] });
  const [events, setEvents] = useState<any[]>([]);
  const [notes, setNotes] = useState("");
  const [notesSaved, setNotesSaved] = useState(false);
  const evRef = useRef<HTMLDivElement>(null);

  const load = async () => {
    try {
      const t = await api(`/api/tasks/${id}`);
      setTask(t);
      setNotes(t.task?.notes || "");
      const g = await api(`/api/tasks/${id}/graph`);
      setGraph(g);
    } catch {}
  };

  useEffect(() => {
    load();
    // 状态/图用慢轮询兜底（SSE 负责实时活动流）
    const iv = setInterval(load, 4000);

    // SSE 活动流：带指数退避自动重连
    let src: EventSource | null = null;
    let retry = 0;
    const connect = () => {
      src = new EventSource(`/api/tasks/${id}/events`);
      src.onmessage = (msg) => {
        try {
          const d = JSON.parse(msg.data);
          setEvents((prev) => [...prev.slice(-199), d]);
        } catch {}
      };
      src.onerror = () => {
        src?.close();
        const delay = Math.min(30000, 1000 * Math.pow(2, retry));
        retry++;
        timer = window.setTimeout(connect, delay);
      };
      src.onopen = () => {
        retry = 0;
      };
    };
    let timer: number | undefined;
    connect();

    return () => {
      clearInterval(iv);
      src?.close();
      if (timer) window.clearTimeout(timer);
    };
  }, [id]);

  useEffect(() => {
    if (evRef.current) evRef.current.scrollTop = evRef.current.scrollHeight;
  }, [events]);

  const saveNotes = async () => {
    await api(`/api/tasks/${id}/notes`, {
      method: "POST",
      body: JSON.stringify({ notes }),
    });
    setNotesSaved(true);
    setTimeout(() => setNotesSaved(false), 1500);
  };

  const exportReport = (fmt: string) => {
    const url = `/api/tasks/${id}/report?format=${fmt}`;
    if (fmt === "markdown") {
      window.open(url, "_blank");
    } else {
      // JSON 下载
      api(url).then((d) => {
        const blob = new Blob([JSON.stringify(d, null, 2)], { type: "application/json" });
        const a = document.createElement("a");
        a.href = URL.createObjectURL(blob);
        a.download = `report-task-${id}.json`;
        a.click();
        URL.revokeObjectURL(a.href);
      });
    }
  };

  const nodes = graph.nodes || [];
  const edges = graph.edges || [];
  const colW = 200;
  const typeIdx: any = { goal: 0, intent: 1, fact: 2, finding: 3, hint: 4 };
  const pos: any = {};
  nodes.forEach((n: any) => {
    const c = typeIdx[n.type] ?? 1;
    const same = nodes.filter((x: any) => x.type === n.type);
    const r = same.indexOf(n);
    pos[n.id] = { x: c * colW + 20, y: r * 56 + 30 };
  });

  return (
    <div className="app">
      <Nav />
      <h1>任务详情 #{id}</h1>
      {task && (
        <div className="card">
          <div className="status-row">
            <h2 style={{ flex: 1 }}>{task.task?.name}</h2>
            <button className="btn ghost" onClick={() => exportReport("json")}>导出 JSON</button>
            <button className="btn ghost" onClick={() => exportReport("markdown")}>导出 Markdown</button>
          </div>
          <p>
            <span className="tag">{task.task?.status}</span>
            {task.running && <span className="dot running" />}
          </p>
          {task.task?.error && (
            <p className="act-item">
              <span className="err">错误：{task.task.error}</span>
            </p>
          )}
          <p className="muted">Goal：{task.task?.goal}</p>
          <p className="muted">范围：{(task.scope || []).map((s: any) => s.pattern).join(", ")}</p>
          <p className="muted">
            发现 {task.findings?.length || 0} 个漏洞 · Token {task.task?.tokens_in}/
            {task.task?.tokens_out}
          </p>
          <div className="status-row" style={{ marginTop: 8 }}>
            <input
              style={{ flex: 1, marginBottom: 0 }}
              placeholder="备注/标签（如：已确认授权范围）"
              value={notes}
              onChange={(e) => setNotes(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && saveNotes()}
            />
            <button className="btn" onClick={saveNotes}>
              {notesSaved ? "已保存" : "保存备注"}
            </button>
          </div>
        </div>
      )}
      <div className="grid2">
        <div className="card">
          <h2>探索图（{nodes.length} 节点 / {edges.length} 边）</h2>
          <svg className="graph-svg" width="100%" height={Math.max(300, nodes.length * 30)} viewBox="0 0 1000 600">
            {edges.map((e: any) => {
              const a = pos[e.from_node_id];
              const b = pos[e.to_node_id];
              if (!a || !b) return null;
              return <line key={e.id} className="edge" x1={a.x + 140} y1={a.y + 14} x2={b.x} y2={b.y + 14} />;
            })}
            {nodes.map((n: any) => {
              const p = pos[n.id] || { x: 20, y: 30 };
              return (
                <g key={n.id} className={`node-${n.type}`} transform={`translate(${p.x},${p.y})`}>
                  <rect width="140" height="28" rx="6" />
                  <text x="70" y="18" textAnchor="middle">
                    {String(n.type).slice(0, 3)}#{n.id} {String(n.status)}
                  </text>
                </g>
              );
            })}
          </svg>
        </div>
        <div className="card">
          <h2>活动流（SSE 实时）</h2>
          <div ref={evRef} style={{ maxHeight: 420, overflowY: "auto" }}>
            {events.map((a: any) => (
              <div key={a.id} className="act-item">
                <span className="t">#{a.id}</span> [{a.role}] {a.step || ""}
                {a.tool && <span className="tool"> {a.tool}</span>}{" "}
                <span className={a.status === "ok" ? "ok" : a.status === "denied" ? "den" : "err"}>
                  {a.status}
                </span>
                {a.output?.text && <pre>{String(a.output.text).slice(0, 500)}</pre>}
              </div>
            ))}
            {events.length === 0 && <p className="muted">等待活动…</p>}
          </div>
        </div>
      </div>
      <div className="card">
        <h2>节点详情</h2>
        {nodes.map((n: any) => (
          <div key={n.id} className="act-item">
            <span className="t">#{n.id}</span> <span className="tag">{n.type}</span>
            <span className="tag">{n.status}</span>{" "}
            {n.title}
          </div>
        ))}
      </div>
    </div>
  );
}