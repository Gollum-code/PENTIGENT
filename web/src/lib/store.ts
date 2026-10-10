"use client";
import { create } from "zustand";

export const API = "";

type State = {
  token: string | null;
  setupNeeded: boolean;
  setToken: (t: string | null) => void;
  setSetupNeeded: (v: boolean) => void;
};

const stored =
  typeof window !== "undefined" ? window.localStorage.getItem("pentigent_token") : null;

export const useAuth = create<State>((set) => ({
  token: stored,
  setupNeeded: false,
  setToken: (t) => {
    if (typeof window !== "undefined") {
      if (t) window.localStorage.setItem("pentigent_token", t);
      else window.localStorage.removeItem("pentigent_token");
    }
    set({ token: t });
  },
  setSetupNeeded: (v) => set({ setupNeeded: v }),
}));

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

export async function api(path: string, opts: RequestInit = {}) {
  const token =
    typeof window !== "undefined" ? window.localStorage.getItem("pentigent_token") : null;
  const headers: any = { "Content-Type": "application/json", ...(opts.headers || {}) };
  if (token) headers.Authorization = `Bearer ${token}`;
  const res = await fetch(API + path, { ...opts, headers });
  const text = await res.text();
  let data: any = {};
  try {
    data = text ? JSON.parse(text) : {};
  } catch {
    data = { error: text };
  }
  if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
  return data;
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