"use client";
import { create } from "zustand";

export const API = "";

type State = {
  token: string | null;
  setupNeeded: boolean;
  setToken: (t: string | null) => void;
  setSetupNeeded: (v: boolean) => void;
};

export const useAuth = create<State>((set) => ({
  // token 只保存在内存里；真正的鉴权凭据是服务端下发的 HttpOnly cookie
  //（JS 读不到，XSS 无法窃取）。setToken 仅用于 UI 状态。
  token: null,
  setupNeeded: false,
  setToken: (t) => set({ token: t }),
  setSetupNeeded: (v) => set({ setupNeeded: v }),
}));

// pageVisible 标签页是否可见。后台标签页无需继续轮询 —— 仪表盘/审批/统计这些
// 每 3~5s 拉一次的定时器在切走时是无谓的请求与耗电。
export function pageVisible(): boolean {
  return typeof document === "undefined" || document.visibilityState === "visible";
}

// ---- 全局错误提示（toast） ----

export const useToast = create<{
  msg: string | null;
  type: "ok" | "err";
  show: (m: string, type?: "ok" | "err") => void;
}>((set) => ({
  msg: null,
  type: "err",
  show: (m, type = "err") => {
    set({ msg: m, type });
    setTimeout(() => set({ msg: null }), 3500);
  },
}));

// 鉴权走同源 HttpOnly cookie（fetch/EventSource 自动携带）；
// Authorization 头只给命令行/外部 API 客户端用，前端不再持有 token。
function authHeaders(base?: HeadersInit): any {
  return { ...(base || {}) };
}

// 401 统一回登录页（登录/初始化接口本身除外）
function handleUnauthorized(path: string, status: number) {
  if (status !== 401 || typeof window === "undefined") return;
  if (path.startsWith("/api/auth/")) return;
  if (!window.location.pathname.startsWith("/login")) window.location.href = "/login/";
}

export async function api(path: string, opts: RequestInit = {}) {
  const headers = authHeaders({ "Content-Type": "application/json", ...(opts.headers || {}) });
  const res = await fetch(API + path, { ...opts, headers });
  const text = await res.text();
  let data: any = {};
  try {
    data = text ? JSON.parse(text) : {};
  } catch {
    data = { error: text };
  }
  if (!res.ok) {
    handleUnauthorized(path, res.status);
    throw new Error(data.error || `HTTP ${res.status}`);
  }
  return data;
}

// apiText：非 JSON 响应（Markdown/CSV 导出）走 fetch（cookie 自动携带），避免 window.open 401
export async function apiText(path: string, opts: RequestInit = {}) {
  const res = await fetch(API + path, { ...opts, headers: authHeaders(opts.headers) });
  const text = await res.text();
  if (!res.ok) {
    handleUnauthorized(path, res.status);
    let msg = `HTTP ${res.status}`;
    try {
      msg = JSON.parse(text).error || msg;
    } catch {}
    throw new Error(msg);
  }
  return text;
}

// apiSafe：失败时弹 toast，不抛异常（配合全局 Toast 组件）
export async function apiSafe(path: string, opts: RequestInit = {}, okMsg?: string) {
  try {
    const d = await api(path, opts);
    if (okMsg) useToast.getState().show(okMsg, "ok");
    return d;
  } catch (e: any) {
    useToast.getState().show(e?.message || "请求失败");
    return null;
  }
}