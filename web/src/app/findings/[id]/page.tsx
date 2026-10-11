import { use } from "react";
import FindingDetail from "@/components/FindingDetail";

export function generateStaticParams() {
  // 静态导出：预生成 1..200 的漏洞详情页骨架（客户端按 id 拉取真实数据）
  return Array.from({ length: 200 }, (_, i) => ({ id: String(i + 1) }));
}

export default function Page({ params }: { params: Promise<{ id: string }> }) {
  const { id } = use(params);
  return <FindingDetail id={id} />;
}