# ARTEX MVP - live end-to-end test (Windows PowerShell)
# Usage:  .\e2e-test.ps1
# Requires: artex.exe running on http://127.0.0.1:8080

$ErrorActionPreference = "Stop"
$base = if ($env:ARTEX_BASE) { $env:ARTEX_BASE } else { "http://127.0.0.1:8080" }
$pass = 0; $fail = 0
function Check($name, $cond) {
  if ($cond) { $script:pass++; Write-Output "  [PASS] $name" }
  else { $script:fail++; Write-Output "  [FAIL] $name" }
}

Write-Output "=== 1. health ==="
$h = Invoke-RestMethod -Uri "$base/api/health" -TimeoutSec 5
Write-Output "  llm=$($h.llm) mock=$($h.mock) setup=$($h.setup) version=$($h.version)"
Check "health ok" ($h.status -eq "ok")

Write-Output "=== 1b. LLM connectivity probe ==="
$llm = Invoke-RestMethod -Uri "$base/api/llm/test" -Method Post -TimeoutSec 30
Write-Output "  llm=$($llm.llm) info=$($llm.info)"
Check "llm available" ($llm.llm -ne "")

Write-Output "=== 2. auth ==="
if (-not $h.setup) {
  $auth = Invoke-RestMethod -Uri "$base/api/auth/setup" -Method Post -Body '{"password":"admin123"}' -ContentType "application/json" -TimeoutSec 10
} else {
  $auth = Invoke-RestMethod -Uri "$base/api/auth/login" -Method Post -Body '{"password":"admin123"}' -ContentType "application/json" -TimeoutSec 10
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
$el = 0; $done = $false
do {
  Start-Sleep -Seconds 2; $el += 2
  $t = Invoke-RestMethod -Uri "$base/api/tasks/$tid" -Method Get -Headers $headers -TimeoutSec 10
  Write-Output ("  {0}s status={1} findings={2} tokIn={3} tokOut={4}" -f $el, $t.task.status, $t.findings.Count, $t.task.tokens_in, $t.task.tokens_out)
  if ($t.task.status -eq "done" -or $t.task.status -eq "failed") { $done = $true }
} while (-not $done -and $el -lt 120)
Check "task completed" $done
Check "task done (not failed)" ($t.task.status -eq "done")
Check "findings produced" ($t.findings.Count -gt 0)
Check "tokens recorded" ($t.task.tokens_in -gt 0)

Write-Output "=== 7. exploration graph ==="
$g = Invoke-RestMethod -Uri "$base/api/tasks/$tid/graph" -Method Get -Headers $headers -TimeoutSec 10
$goals = @($g.nodes | Where-Object { $_.type -eq "goal" })
$intents = @($g.nodes | Where-Object { $_.type -eq "intent" })
$facts = @($g.nodes | Where-Object { $_.type -eq "fact" })
$finds = @($g.nodes | Where-Object { $_.type -eq "finding" })
Write-Output "  goals=$($goals.Count) intents=$($intents.Count) facts=$($facts.Count) findings=$($finds.Count) edges=$($g.edges.Count)"
Check "goals all met" (@($goals | Where-Object { $_.status -ne "met" }).Count -eq 0)
Check "intents all done" (@($intents | Where-Object { $_.status -ne "done" }).Count -eq 0)
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
Check "findings list" ($f.findings.Count -gt 0)

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

Write-Output "=== 12. delete task ==="
Invoke-RestMethod -Uri "$base/api/tasks/$tid" -Method Delete -Headers $headers -TimeoutSec 10 | Out-Null
Check "task deleted" $true

Write-Output ""
Write-Output "==========================================="
Write-Output "  PASS: $pass   FAIL: $fail"
Write-Output "==========================================="
if ($fail -gt 0) { exit 1 }
exit 0