"use client";
import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { api, useAuth } from "@/lib/store";

// 登录 / 首次初始化管理员密码。
// auth.disabled=true 时直接回首页（本地演示模式）。
export default function LoginPage() {
  const router = useRouter();
  const { setToken } = useAuth();
  const [mode, setMode] = useState<"loading" | "setup" | "login" | "done">("loading");
  const [pw, setPw] = useState("");
  const [pw2, setPw2] = useState("");
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    api("/api/health")
      .then((h) => {
        if (h.auth_disabled) {
          router.replace("/");
          return;
        }
        setMode(h.setup ? "login" : "setup");
      })
      .catch(() => setMode("login"));
  }, [router]);

  const submit = async () => {
    setErr("");
    if (mode === "setup") {
      if (pw.length < 6) return setErr("密码至少 6 位");
      if (pw !== pw2) return setErr("两次输入的密码不一致");
    }
    if (!pw) return setErr("请输入密码");
    setBusy(true);
    try {
      const path = mode === "setup" ? "/api/auth/setup" : "/api/auth/login";
      const d = await api(path, {
        method: "POST",
        body: JSON.stringify({ password: pw }),
      });
      if (d.token) setToken(d.token);
      setMode("done");
      router.replace("/");
    } catch (e: any) {
      setErr(e?.message || "请求失败");
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="app">
      <h1>PENTIGENT</h1>
      <div className="card" style={{ maxWidth: 420 }}>
        <h2>{mode === "setup" ? "首次初始化" : "登录"}</h2>
        {mode === "loading" ? (
          <p className="muted">检查初始化状态…</p>
        ) : (
          <>
            <label>{mode === "setup" ? "设置管理员密码（至少 6 位）" : "管理员密码"}</label>
            <input
              type="password"
              value={pw}
              autoFocus
              onChange={(e) => setPw(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && submit()}
            />
            {mode === "setup" && (
              <>
                <label>再次输入密码</label>
                <input
                  type="password"
                  value={pw2}
                  onChange={(e) => setPw2(e.target.value)}
                  onKeyDown={(e) => e.key === "Enter" && submit()}
                />
              </>
            )}
            {err && <p className="err">{err}</p>}
            <button className="btn" disabled={busy} onClick={submit} style={{ marginTop: 8 }}>
              {busy ? "请稍候…" : mode === "setup" ? "初始化并登录" : "登录"}
            </button>
          </>
        )}
      </div>
    </div>
  );
}
