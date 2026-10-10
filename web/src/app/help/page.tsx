"use client";
import Nav from "@/components/Nav";

export default function Help() {
  return (
    <div className="app">
      <Nav />
      <h1>使用指南</h1>

      <div className="card">
        <h2>什么是 PENTIGENT</h2>
        <p>
          给一个任务目标和描述，系统自己决定"先干什么、再干什么"，用真实工具（bash / HTTP）
          探测目标资产，把发现写回数据库，直到证明目标达成或没有新方向收敛。
        </p>
      </div>

      <div className="card">
        <h2>快速开始（30 秒）</h2>
        <ol style={{ marginLeft: 20 }}>
          <li>仪表盘点 <b>新建任务</b></li>
          <li>目标 Goal 填：<code>探测 example.com 的资产面并发现 Web 漏洞</code></li>
          <li>授权范围填：<code>example.com</code>（硬边界，越权目标会被拒绝）</li>
          <li>创建 → 启动 → 看探索图和活动流实时推进</li>
        </ol>
      </div>

      <div className="card">
        <h2>核心概念</h2>
        <table>
          <thead>
            <tr><th>概念</th><th>说明</th></tr>
          </thead>
          <tbody>
            <tr><td>Goal（目标）</td><td>任务要达到的目标，planner 会分解并追踪达成状态</td></tr>
            <tr><td>Intent（意图）</td><td>一条可执行的探测方向，多个意图并发执行</td></tr>
            <tr><td>Fact（事实）</td><td>探测出的结论（如：example.com 存在 Web 服务）</td></tr>
            <tr><td>Finding（漏洞）</td><td>确认的漏洞，含严重性与证据</td></tr>
            <tr><td>授权范围 Scope</td><td>任务只能探测范围内的目标，范围外被硬拦截</td></tr>
            <tr><td>审批门</td><td>危险/可疑操作需人工在"审批"页放行</td></tr>
          </tbody>
        </table>
      </div>

      <div className="card">
        <h2>安全边界（重要）</h2>
        <ul style={{ marginLeft: 20 }}>
          <li>所有 bash / HTTP 请求的目标必须在任务授权范围内，范围外由代码硬判拒绝</li>
          <li>内置拒绝规则：<code>rm -rf</code>、<code>/etc/shadow</code>、云元数据端点等</li>
          <li>危险操作进"审批"队列，人工放行后才执行</li>
          <li>本系统仅用于<b>已授权</b>的渗透测试</li>
        </ul>
      </div>

      <div className="card">
        <h2>页面导航</h2>
        <table>
          <thead>
            <tr><th>页面</th><th>用途</th></tr>
          </thead>
          <tbody>
            <tr><td>仪表盘</td><td>任务列表、统计卡片、新建/启动/停止任务</td></tr>
            <tr><td>任务详情</td><td>探索图、实时活动流、导出报告、备注</td></tr>
            <tr><td>资产</td><td>全局资产库，查看每个资产被哪些意图测试过</td></tr>
            <tr><td>发现</td><td>漏洞列表（按严重性筛选），链接回所属任务</td></tr>
            <tr><td>审批</td><td>人工审批队列 + 拦截规则</td></tr>
          </tbody>
        </table>
      </div>

      <div className="card">
        <h2>导出报告</h2>
        <p>任务详情页可导出 <b>JSON</b>（完整数据）或 <b>Markdown</b>（可交付报告），
        含目标、授权范围、资产清单、漏洞详情（按严重性排序）、资产测试覆盖。</p>
      </div>

      <div className="card">
        <h2>故障排查</h2>
        <ul style={{ marginLeft: 20 }}>
          <li><b>任务一直 running</b>：worker 可能卡在网络请求上，5 分钟后会自动回收重跑</li>
          <li><b>状态显示 incomplete</b>：planner 无新方向但目标未全部达成，查看错误信息</li>
          <li><b>无漏洞发现</b>：目标可能安全，或网络不可达；尝试换一个明确的目标</li>
          <li><b>服务启动失败</b>：查看 <code>logs/artex.log</code>，确认 PostgreSQL 已启动</li>
        </ul>
      </div>
    </div>
  );
}