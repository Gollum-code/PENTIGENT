import type { Metadata } from "next";
import Toast from "@/components/Toast";
import ErrorBoundary from "@/components/ErrorBoundary";
import "./globals.css";

export const metadata: Metadata = {
  title: "PENTIGENT · AI 渗透测试系统",
  description: "双图架构 + planner/worker 事件驱动闭环",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="zh-CN">
      <body>
        <ErrorBoundary>
          {children}
          <Toast />
        </ErrorBoundary>
      </body>
    </html>
  );
}