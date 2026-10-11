"use client";
import { Component } from "react";

// ErrorBoundary 防止单个组件异常导致整页白屏
export default class ErrorBoundary extends Component<
  { children: React.ReactNode },
  { error: Error | null }
> {
  state = { error: null as Error | null };

  static getDerivedStateFromError(error: Error) {
    return { error };
  }

  componentDidCatch(error: Error, info: React.ErrorInfo) {
    console.error("页面组件异常:", error, info?.componentStack);
  }

  render() {
    if (this.state.error) {
      return (
        <div className="app">
          <div className="card">
            <h2>页面出错了</h2>
            <p className="muted">
              界面遇到异常：<code>{String(this.state.error.message)}</code>
            </p>
            <button className="btn" onClick={() => this.setState({ error: null })}>
              重试
            </button>
            <button className="btn ghost" onClick={() => (window.location.href = "/")}>
              回到仪表盘
            </button>
          </div>
        </div>
      );
    }
    return this.props.children;
  }
}