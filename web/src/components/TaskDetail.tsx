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
  const [history, setHistory] = useState<any[]>([]);
  const [zoom, setZoom] = useState(1);
  const [pan, setPan] = useState({ x: 0, y: 0 });
  const [selectedNode, setSelectedNode] = useState<number | null>(null);
  const [dragging, setDragging] = useState(false);
  const dragRef = useRef<{ x: number; y: number; px: number; py: number } | null>(null);
  const evRef = useRef<HTMLDivElement>(null);

  const load = async () => {
    try {
      const t = await api(`/api/tasks/${id}`);
      setTask(t);
      setNotes(t.task?.notes || "");
      const g = await api(`/api/tasks/${id}/graph`);
      setGraph(g);
      const h = await api(`/api/tasks/${id}/history`);
      setHistory(h.history || []);
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
  const basePos: any = {};
  nodes.forEach((n: any) => {
    const c = typeIdx[n.type] ?? 1;
    const same = nodes.filter((x: any) => x.type === n.type);
    const r = same.indexOf(n);
    basePos[n.id] = { x: c * colW + 20, y: r * 56 + 30 };
  });
  // 应用缩放/平移
  const pos: any = {};
  nodes.forEach((n: any) => {
    const b = basePos[n.id];
    if (b) pos[n.id] = { x: b.x * zoom + pan.x, y: b.y * zoom + pan.y };
  });
  const sel = selectedNode != null ? nodes.find((n: any) => n.id === selectedNode) : null;

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
      {history.length > 0 && (
        <div className="card">
          <h2>运行历史（{history.length} 轮）</h2>
          <table>
            <thead>
              <tr>
                <th>轮次</th>
                <th>状态</th>
                <th>节点</th>
                <th>意图</th>
                <th>事实</th>
                <th>漏洞</th>
                <th>开始</th>
              </tr>
            </thead>
            <tbody>
              {history.map((h, idx) => (
                <tr key={h.exploration_id}>
                  <td>#{history.length - idx}</td>
                  <td>
                    <span className="tag gray">{h.status}</span>
                  </td>
                  <td>{h.nodes}</td>
                  <td>{h.intents}</td>
                  <td>{h.facts}</td>
                  <td>{h.findings}</td>
                  <td className="muted">{String(h.created_at).slice(0, 19)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      <div className="grid2">
        <div className="card">
          <div className="status-row">
            <h2 style={{ flex: 1 }}>探索图（{nodes.length} 节点 / {edges.length} 边）</h2>
            <button className="btn ghost" onClick={() => setZoom((z) => Math.max(0.5, z - 0.2))}>−</button>
            <span className="muted">{Math.round(zoom * 100)}%</span>
            <button className="btn ghost" onClick={() => setZoom((z) => Math.min(2, z + 0.2))}>+</button>
            <button className="btn ghost" onClick={() => { setZoom(1); setPan({ x: 0, y: 0 }); }}>重置</button>
          </div>
          <svg
            className="graph-svg"
            width="100%"
            height={360}
            style={{ cursor: dragging ? "grabbing" : "grab", border: "1px solid #30363d", borderRadius: 6 }}
            onMouseDown={(e) => {
              dragRef.current = { x: e.clientX, y: e.clientY, px: pan.x, py: pan.y };
              setDragging(true);
            }}
            onMouseMove={(e) => {
              if (dragRef.current) {
                setPan({
                  x: dragRef.current.px + (e.clientX - dragRef.current.x),
                  y: dragRef.current.py + (e.clientY - dragRef.current.y),
                });
              }
            }}
            onMouseUp={() => { dragRef.current = null; setDragging(false); }}
            onMouseLeave={() => { dragRef.current = null; setDragging(false); }}
            onWheel={(e) => setZoom((z) => Math.max(0.5, Math.min(2, z - e.deltaY * 0.001)))}
          >
            {edges.map((e: any) => {
              const a = pos[e.from_node_id];
              const b = pos[e.to_node_id];
              if (!a || !b) return null;
              return <line key={e.id} className="edge" x1={a.x + 140} y1={a.y + 14} x2={b.x} y2={b.y + 14} />;
            })}
            {nodes.map((n: any) => {
              const p = pos[n.id] || { x: 20, y: 30 };
              const isSel = selectedNode === n.id;
              return (
                <g
                  key={n.id}
                  className={`node-${n.type}`}
                  transform={`translate(${p.x},${p.y})`}
                  onClick={(e) => { e.stopPropagation(); setSelectedNode(n.id); }}
                  style={{ cursor: "pointer" }}
                >
                  <rect
                    width="140"
                    height="28"
                    rx="6"
                    stroke={isSel ? "#58a6ff" : "transparent"}
                    strokeWidth="2"
                  />
                  <text x="70" y="18" textAnchor="middle">
                    {String(n.type).slice(0, 3)}#{n.id} {String(n.status)}
                  </text>
                </g>
              );
            })}
          </svg>
          {sel ? (
            <div className="act-item" style={{ marginTop: 8 }}>
              <span className="t">#{sel.id}</span>{" "}
              <span className="tag">{sel.type}</span>{" "}
              <span className="tag gray">{sel.status}</span>
              <div style={{ marginTop: 4 }}>{sel.title}</div>
              {sel.content?.description && (
                <div className="muted" style={{ marginTop: 4 }}>{sel.content.description}</div>
              )}
              <button className="btn ghost" style={{ marginTop: 6 }} onClick={() => setSelectedNode(null)}>
                关闭
              </button>
            </div>
          ) : (
            <p className="muted" style={{ marginTop: 6 }}>点击节点查看详情 · 拖动平移 · 滚轮缩放</p>
          )}
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