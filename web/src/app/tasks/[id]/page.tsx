import { use } from "react";
import TaskDetail from "@/components/TaskDetail";

export function generateStaticParams() {
  // 静态导出：预生成 1..100 的任务页骨架（客户端按 id 拉取真实数据）
  return Array.from({ length: 100 }, (_, i) => ({ id: String(i + 1) }));
}

export default function Page({ params }: { params: Promise<{ id: string }> }) {
  const { id } = use(params);
  return <TaskDetail id={id} />;
}