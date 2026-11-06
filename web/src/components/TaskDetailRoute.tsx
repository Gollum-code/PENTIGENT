"use client";
import { useEffect, useState } from "react";
import { usePathname } from "next/navigation";
import TaskDetail from "@/components/TaskDetail";

// 静态导出只为 /tasks/1/ 预生成一个壳，任意 id 都复用该壳。
// 真实 id 从浏览器 URL 读取，避免再依赖根页面做路径分发。
export default function TaskDetailRoute() {
  const pathname = usePathname() || "";
  const [mounted, setMounted] = useState(false);
  useEffect(() => setMounted(true), []);

  // 挂载前不渲染，避免服务端壳（id=1）与客户端真实 id 的 hydration 不一致
  if (!mounted) return null;

  const m = pathname.match(/\/tasks\/(\d+)/);
  if (!m) {
    return (
      <div className="app">
        <p className="muted">无效的任务地址</p>
      </div>
    );
  }
  return <TaskDetail id={m[1]} />;
}
