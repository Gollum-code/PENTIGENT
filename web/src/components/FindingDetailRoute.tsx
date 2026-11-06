"use client";
import { useEffect, useState } from "react";
import { usePathname } from "next/navigation";
import FindingDetail from "@/components/FindingDetail";

// 同 TaskDetailRoute：任意漏洞 id 复用 /findings/1/ 的静态壳。
export default function FindingDetailRoute() {
  const pathname = usePathname() || "";
  const [mounted, setMounted] = useState(false);
  useEffect(() => setMounted(true), []);

  if (!mounted) return null;

  const m = pathname.match(/\/findings\/(\d+)/);
  if (!m) {
    return (
      <div className="app">
        <p className="muted">无效的漏洞地址</p>
      </div>
    );
  }
  return <FindingDetail id={m[1]} />;
}
