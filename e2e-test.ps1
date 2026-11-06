# PENTIGENT MVP - live end-to-end test (Windows PowerShell)
# Usage:  .\e2e-test.ps1
# Requires: pentigent.exe running on http://127.0.0.1:8080

$ErrorActionPreference = "Stop"
$base = if ($env:PENTIGENT_BASE) { $env:PENTIGENT_BASE } else { "http://127.0.0.1:8080" }
$pass = 0; $fail = 0
function Check($name, $cond) {
  if ($cond) { $script:pass++; Write-Output "  [PASS] $name" }
  else { $script:fail++; Write-Output "  [FAIL] $name" }
}

Write-Output "=== 1. health ==="
$h = Invoke-RestMethod -Uri "$base/api/health" -TimeoutSec 5
Write-Output "  llm=$($h.llm) mock=$($h.mock) setup=$($h.setup) version=$($h.version)"
Check "health ok" ($h.status -in @("ok","degraded"))

Write-Output "=== 1b. LLM connectivity probe ==="
$llm = Invoke-RestMethod -Uri "$base/api/llm/test" -Method Post -TimeoutSec 30
Write-Output "  llm=$($llm.llm) info=$($llm.info)"
Check "llm available" ($llm.llm -ne "")

Write-Output "=== 2. auth ==="
# 可用 PENTIGENT_ADMIN_PASSWORD 覆盖；忘记密码时运行： .\pentigent.exe -reset-admin config.json
$adminPass = if ($env:PENTIGENT_ADMIN_PASSWORD) { $env:PENTIGENT_ADMIN_PASSWORD } else { "admin123" }
$authBody = @{ password = $adminPass } | ConvertTo-Json -Compress
if (-not $h.setup) {
  $auth = Invoke-RestMethod -Uri "$base/api/auth/setup" -Method Post -Body $authBody -ContentType "application/json" -TimeoutSec 10
} else {
  try {
    $auth = Invoke-RestMethod -Uri "$base/api/auth/login" -Method Post -Body $authBody -ContentType "application/json" -TimeoutSec 10
  } catch {
    Write-Output "  登录失败：管理员密码不是默认值。设置 PENTIGENT_ADMIN_PASSWORD，或运行 .\pentigent.exe -reset-admin config.json 重置后重试。"
    throw
  }
}
$headers = @{ Authorization = "Bearer $($auth.token)" }
Check "token issued" ($auth.token.Length -gt 20)

Write-Output "=== 3. unauthorized rejected ==="
if ($h.auth_disabled) {
  Write-Output "  (auth disabled, skipped)"
} else {
  $unauth = $false
  try { Invoke-RestMethod -Uri "$base/api/tasks" -Method Get -TimeoutSec 5 | Out-Null } catch { $unauth = $true }
  Check "unauth rejected" $unauth
}

Write-Output "=== 3.5 unknown API returns JSON 404 ==="
$unknownStatus = 0; $unknownJson = $false
try {
  Invoke-WebRequest -Uri "$base/api/definitely-not-a-route" -Method Get -Headers $headers -TimeoutSec 5 -ErrorAction Stop | Out-Null
} catch {
  $unknownStatus = [int]$_.Exception.Response.StatusCode
  try {
    $bodyText = (New-Object System.IO.StreamReader($_.Exception.Response.GetResponseStream())).ReadToEnd()
    $unknownJson = ($bodyText -match '"error"')
  } catch { $unknownJson = $false }
}
Check "unknown api 404" ($unknownStatus -eq 404)
Check "unknown api json" $unknownJson

Write-Output "=== 4. create task (example.com live target) ==="
$body = @{ name = "live-test"; goal = "Probe example.com assets and find web vulnerabilities"; description = "authorized pentest of example.com"; scope = @("example.com") } | ConvertTo-Json -Compress
$task = Invoke-RestMethod -Uri "$base/api/tasks" -Method Post -Body $body -ContentType "application/json" -Headers $headers -TimeoutSec 15
$tid = $task.id
Write-Output "  task id=$tid"
Check "task created" ($tid -gt 0)

Write-Output "=== 5. start task ==="
Invoke-RestMethod -Uri "$base/api/tasks/$tid/start" -Method Post -Headers $headers -TimeoutSec 10 | Out-Null
Check "task started" $true

Write-Output "=== 6. poll until done ==="
# 真实 LLM 每个意图多轮工具交互，需要远多于 mock 的时间
$maxWait = 120
if ($h.mock -ne $true) {
  $maxWait = 600
  Write-Output "  (检测到真实 LLM，轮询窗口延长到 ${maxWait}s)"
}
$el = 0; $done = $false
do {
  Start-Sleep -Seconds 2; $el += 2
  $t = Invoke-RestMethod -Uri "$base/api/tasks/$tid" -Method Get -Headers $headers -TimeoutSec 10
  Write-Output ("  {0}s status={1} findings={2} tokIn={3} tokOut={4}" -f $el, $t.task.status, $t.findings.Count, $t.task.tokens_in, $t.task.tokens_out)
  if ($t.task.status -eq "done" -or $t.task.status -eq "failed" -or $t.task.status -eq "incomplete") { $done = $true }
} while (-not $done -and $el -lt $maxWait)
Check "task completed" $done
$isMock = ($h.mock -eq $true)
if ($isMock) {
  Check "task done (not failed)" ($t.task.status -eq "done")
} else {
  # 真实 LLM 常在预算护栏处收敛为 incomplete：这是预期，不是失败
  Check "task terminal (done/incomplete)" ($t.task.status -in @("done","incomplete"))
}
Check "tokens recorded" ($t.task.tokens_in -gt 0)

Write-Output "=== 7. exploration graph ==="
$g = Invoke-RestMethod -Uri "$base/api/tasks/$tid/graph" -Method Get -Headers $headers -TimeoutSec 10
$goals = @($g.nodes | Where-Object { $_.type -eq "goal" })
$intents = @($g.nodes | Where-Object { $_.type -eq "intent" })
$facts = @($g.nodes | Where-Object { $_.type -eq "fact" })
$finds = @($g.nodes | Where-Object { $_.type -eq "finding" })
Write-Output "  goals=$($goals.Count) intents=$($intents.Count) facts=$($facts.Count) findings=$($finds.Count) edges=$($g.edges.Count)"
if ($isMock) {
  Check "goals all met" (@($goals | Where-Object { $_.status -ne "met" }).Count -eq 0)
  Check "intents all done" (@($intents | Where-Object { $_.status -ne "done" }).Count -eq 0)
} else {
  # 真实 LLM：只要真的自主规划并执行了就算闭环工作正常
  Check "planner produced intents" ($intents.Count -gt 0)
  Check "intents terminal" (@($intents | Where-Object { $_.status -notin @("done","blocked") }).Count -eq 0)
}
Check "facts confirmed" (@($facts | Where-Object { $_.status -ne "confirmed" }).Count -eq 0)
Check "edges created" ($g.edges.Count -gt 0)

Write-Output "=== 8. assets ==="
$a = Invoke-RestMethod -Uri "$base/api/assets" -Method Get -Headers $headers -TimeoutSec 10
Write-Output "  assets=$($a.assets.Count)"
$a.assets | ForEach-Object { Write-Output "   - [$($_.type)] domain=$($_.domain) url=$($_.url)" }
Check "assets discovered" ($a.assets.Count -gt 0)
Check "root_domain asset" (@($a.assets | Where-Object { $_.type -eq "root_domain" }).Count -gt 0)

Write-Output "=== 9. findings ==="
$f = Invoke-RestMethod -Uri "$base/api/findings" -Method Get -Headers $headers -TimeoutSec 10
Write-Output "  findings=$($f.findings.Count)"
$f.findings | ForEach-Object { Write-Output "   - [$($_.severity)] $($_.title)" }
# 真实 LLM 是否报出漏洞取决于目标实际情况（如 example.com 几乎无漏洞），
# 因此只要求"发现页可用"，不强制必须有漏洞。
if ($isMock) {
  Check "findings list" ($f.findings.Count -gt 0)
} else {
  Check "findings api ok" ($null -ne $f.findings)
}

Write-Output "=== 10. SSE activity stream ==="
$sse = & curl.exe -s -N --max-time 4 -H "Authorization: Bearer $($auth.token)" "$base/api/tasks/$tid/events" 2>$null
$sseLines = @($sse | Where-Object { $_ -like "data:*" })
Write-Output "  sse events=$($sseLines.Count)"
Check "sse streamed events" ($sseLines.Count -gt 0)

Write-Output "=== 11. guard / intercept ==="
$p = Invoke-RestMethod -Uri "$base/api/intercept/pending?status=pending" -Method Get -Headers $headers -TimeoutSec 10
Write-Output "  pending=$($p.pending.Count)"
$r = Invoke-RestMethod -Uri "$base/api/intercept/rules" -Method Get -Headers $headers -TimeoutSec 10
Write-Output "  rules=$($r.rules.Count)"
Check "rules loaded" ($r.rules.Count -gt 0)

Write-Output "=== 11b. create custom deny rule (must be enabled) ==="
$ruleBody = @{ name = "e2e-deny-evil"; match_target = "tool_input"; match_type = "regex"; pattern = "denied-example\.com"; action = "deny"; priority = 10 } | ConvertTo-Json -Compress
$rr = Invoke-RestMethod -Uri "$base/api/intercept/rules" -Method Post -Body $ruleBody -ContentType "application/json" -Headers $headers -TimeoutSec 10
Check "rule created" ($rr.id -gt 0)
Check "rule created enabled" ($rr.enabled -eq $true)
$r2 = Invoke-RestMethod -Uri "$base/api/intercept/rules" -Method Get -Headers $headers -TimeoutSec 10
$mine = @($r2.rules | Where-Object { $_.id -eq $rr.id -and $_.enabled -eq $true })
Check "rule persisted enabled" ($mine.Count -eq 1)

Write-Output "=== 11c. bad regex must be rejected ==="
$badRejected = $false
try {
  $badBody = @{ name = "bad"; match_target = "tool_input"; match_type = "regex"; pattern = "([unbalanced"; action = "deny" } | ConvertTo-Json -Compress
  Invoke-RestMethod -Uri "$base/api/intercept/rules" -Method Post -Body $badBody -ContentType "application/json" -Headers $headers -TimeoutSec 10 | Out-Null
} catch { $badRejected = $true }
Check "bad regex rejected" $badRejected
if ($rr.id -gt 0) {
  Invoke-RestMethod -Uri "$base/api/intercept/rules/$($rr.id)" -Method Delete -Headers $headers -TimeoutSec 10 | Out-Null
  Check "test rule cleaned up" $true
}

Write-Output "=== 12. delete task ==="
Invoke-RestMethod -Uri "$base/api/tasks/$tid" -Method Delete -Headers $headers -TimeoutSec 10 | Out-Null
Check "task deleted" $true

Write-Output ""
Write-Output "==========================================="
Write-Output "  PASS: $pass   FAIL: $fail"
Write-Output "==========================================="
if ($fail -gt 0) { exit 1 }
exit 0