"use client";
import { useEffect, useRef, useState } from "react";
import { api, apiText, useToast } from "@/lib/store";
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
  const [sseDown, setSseDown] = useState(false);
  const dragRef = useRef<{ x: number; y: number; px: number; py: number } | null>(null);
  const evRef = useRef<HTMLDivElement>(null);
  // 有新活动或每隔若干次轮询才刷新 graph，避免每 5s 全量拉图
  const needGraphRef = useRef(true);
  const pollRef = useRef(0);

  // full=false 时不重复拉运行历史，减少轮询开销
  const load = async (full = true) => {
    try {
      const t = await api(`/api/tasks/${id}`);
      setTask(t);
      pollRef.current++;
      if (full || needGraphRef.current || pollRef.current % 3 === 0) {
        const g = await api(`/api/tasks/${id}/graph`);
        setGraph(g);
        needGraphRef.current = false;
      }
      if (full) {
        // 只在首次加载回填备注，避免轮询覆盖用户正在输入的内容
        setNotes(t.task?.notes || "");
        const h = await api(`/api/tasks/${id}/history`);
        setHistory(h.history || []);
      }
    } catch (e: any) {
      // 轮询失败不弹提示（避免每 5s 刷屏），但首次加载失败要让用户看到原因
      if (full) useToast.getState().show("加载任务失败: " + (e?.message || "网络错误"));
    }
  };

  useEffect(() => {
    load(true);
    // 状态/图用慢轮询兜底（SSE 负责实时活动流）
    const iv = setInterval(() => load(false), 5000);

    // SSE 活动流：带指数退避自动重连。
    // EventSource 不能设置 Authorization 头，但同源 HttpOnly cookie 会自动携带。
    // 重连时带上 lastEventId（服务端支持 Last-Event-ID/?lastEventId= 补推），
    // 否则每次重连只能拿到最近 50 条，断线期间的事件会缺失。
    let src: EventSource | null = null;
    let retry = 0;
    let closed = false;
    const lastEventIdRef = { id: 0 };
    const connect = () => {
      if (closed) return;
      const qs = lastEventIdRef.id > 0 ? `?lastEventId=${lastEventIdRef.id}` : "";
      src = new EventSource(`/api/tasks/${id}/events${qs}`);
      src.onmessage = (msg) => {
        try {
          const d = JSON.parse(msg.data);
          const prevMax = lastEventIdRef.id;
          if (d.id != null && d.id > prevMax) lastEventIdRef.id = d.id;
          needGraphRef.current = true; // 有新活动 → 下一轮刷新探索图
          setEvents((prev) => {
            // 比已收到的更旧的事件（重连补推/旧批次）：忽略，避免活动流倒序
            if (d.id != null && d.id < prevMax) return prev;
            // 按 activity id 去重：重连补推时不会重复 append
            if (d.id != null && prev.some((x) => x.id === d.id)) return prev;
            return [...prev.slice(-199), d];
          });
        } catch {}
      };
      src.onerror = () => {
        src?.close();
        if (closed) return;
        setSseDown(true);
        const delay = Math.min(30000, 1000 * Math.pow(2, retry));
        retry++;
        timer = window.setTimeout(connect, delay);
      };
      src.onopen = () => {
        retry = 0;
        setSseDown(false);
      };
    };
    let timer: number | undefined;
    connect();

    return () => {
      closed = true;
      clearInterval(iv);
      src?.close();
      if (timer) window.clearTimeout(timer);
    };
  }, [id]);

  useEffect(() => {
    if (evRef.current) evRef.current.scrollTop = evRef.current.scrollHeight;
  }, [events]);

  const saveNotes = async () => {
    try {
      await api(`/api/tasks/${id}/notes`, {
        method: "POST",
        body: JSON.stringify({ notes }),
      });
      setNotesSaved(true);
      setTimeout(() => setNotesSaved(false), 1500);
    } catch (e: any) {
      useToast.getState().show("保存备注失败: " + (e?.message || "网络错误"));
    }
  };

  const download = (content: string, filename: string, type: string) => {
    const blob = new Blob([content], { type });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = filename;
    a.click();
    URL.revokeObjectURL(a.href);
  };

  // 统一走带鉴权的 fetch：window.open 不会带 Authorization 头，开启鉴权后会 401
  const exportReport = async (fmt: string) => {
    try {
      if (fmt === "markdown") {
        const md = await apiText(`/api/tasks/${id}/report?format=markdown`);
        download(md, `report-task-${id}.md`, "text/markdown;charset=utf-8");
      } else {
        const d = await api(`/api/tasks/${id}/report?format=json`);
        download(JSON.stringify(d, null, 2), `report-task-${id}.json`, "application/json");
      }
    } catch (e: any) {
      useToast.getState().show("导出失败: " + (e?.message || "网络错误"));
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
          <h2>
            活动流（SSE 实时）
            {sseDown && (
              <span className="err" style={{ fontSize: 12, marginLeft: 8, fontWeight: "normal" }}>
                连接中断，重连中…
              </span>
            )}
          </h2>
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