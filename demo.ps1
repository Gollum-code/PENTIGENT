# PENTIGENT 示例演示 · 一键跑通完整闭环
# 用法：双击 start.bat 启动服务后，运行 .\demo.ps1
# 会自动：登录 → 建示例任务 → 启动 → 轮询到结束 → 打印探索图/资产/漏洞/活动流

$ErrorActionPreference = "Stop"
$base = if ($env:ARTEX_BASE) { $env:ARTEX_BASE } else { "http://127.0.0.1:8080" }

# PS 5.1 的 Invoke-RestMethod 默认用 ANSI 编码 body，中文会乱码。
# 必须把 JSON 转成 UTF-8 字节并用局部变量直接传给 -Body（不能用函数返回值，会被管道重编码）。
function Post($uri, $body, $hdr) {
  $json = $body | ConvertTo-Json -Compress
  $bytes = [System.Text.Encoding]::UTF8.GetBytes($json)
  if ($hdr) {
    Invoke-RestMethod -Uri "$base$uri" -Method Post -Body $bytes -ContentType "application/json; charset=utf-8" -Headers $hdr
  } else {
    Invoke-RestMethod -Uri "$base$uri" -Method Post -Body $bytes -ContentType "application/json; charset=utf-8"
  }
}

Write-Output "============================================"
Write-Output "  PENTIGENT 示例演示"
Write-Output "============================================"

# 1) 确保服务在线
Write-Output ""
Write-Output "[1/6] 检查服务..."
$h = Invoke-RestMethod -Uri "$base/api/health" -TimeoutSec 5
Write-Output "  $base  (llm=$($h.llm), mock=$($h.mock))"

# 2) 认证
Write-Output ""
Write-Output "[2/6] 认证..."
if (-not $h.setup) {
  $auth = Post "/api/auth/setup" @{ password = "admin123" }
  Write-Output "  首次设置密码 admin123"
} else {
  $auth = Post "/api/auth/login" @{ password = "admin123" }
}
$headers = @{ Authorization = "Bearer $($auth.token)" }
Write-Output "  token 就绪"

# 3) 创建示例任务（针对 example.com 线上真实系统）
Write-Output ""
Write-Output "[3/6] 创建示例任务..."
$task = Post "/api/tasks" @{
  name        = "示例：example.com 资产面与Web漏洞"
  goal        = "对 example.com 做授权资产面与 Web 漏洞探测"
  description = "演示任务：枚举根域/子域名、识别服务指纹、检查常见 Web 漏洞（仅限 example.com）"
  scope       = @("example.com")
} $headers
Write-Output "  任务 #$($task.id) 已创建: $($task.name)"
$tid = $task.id

# 4) 启动
Write-Output ""
Write-Output "[4/6] 启动任务..."
Invoke-RestMethod -Uri "$base/api/tasks/$tid/start" -Method Post -Headers $headers | Out-Null
Write-Output "  已启动，等待 agent 闭环..."

# 5) 轮询到结束（最长 90s）
$el = 0
do {
  Start-Sleep -Seconds 2; $el += 2
  $t = Invoke-RestMethod -Uri "$base/api/tasks/$tid" -Method Get -Headers $headers
  Write-Output ("  {0}s status={1} 发现={2}" -f $el, $t.task.status, $t.findings.Count)
} while ($t.task.status -notin @("done","failed","incomplete") -and $el -lt 90)

# 6) 打印成果
Write-Output ""
Write-Output "[5/6] 探索图（goals → intents → facts → findings）..."
$g = Invoke-RestMethod -Uri "$base/api/tasks/$tid/graph" -Method Get -Headers $headers
$typeLabel = @{ goal = "目标"; intent = "意图"; fact = "事实"; finding = "漏洞"; hint = "提示" }
foreach ($n in $g.nodes) {
  $lb = $typeLabel[$n.type]; if (-not $lb) { $lb = $n.type }
  Write-Output ("    [{0}] {1,-10} #{2}  {3}" -f $lb, $n.status, $n.id, $n.title)
}
Write-Output "    边关系: $($g.edges.Count) 条"

Write-Output ""
Write-Output "[6/6] 成果汇总..."
$a = Invoke-RestMethod -Uri "$base/api/assets" -Method Get -Headers $headers
$f = Invoke-RestMethod -Uri "$base/api/findings" -Method Get -Headers $headers
Write-Output ("  资产: {0} 个" -f $a.total)
foreach ($asset in $a.assets) { Write-Output ("    - [{0}] {1}{2}" -f $asset.type, $asset.domain, $(if ($asset.url) { "  $($asset.url)" } else { "" })) }
Write-Output ("  漏洞: {0} 个" -f $f.total)
foreach ($fd in $f.findings) { Write-Output ("    - [{0}] {1}" -f $fd.severity, $fd.title) }
Write-Output ("  Token 消耗: in={0} out={1}" -f $t.task.tokens_in, $t.task.tokens_out)

Write-Output ""
Write-Output "============================================"
Write-Output "  演示完成！浏览器打开 $base 看可视化"
Write-Output "  （任务详情: $base/tasks/$tid/）"
Write-Output "============================================"