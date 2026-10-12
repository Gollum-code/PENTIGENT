# ============================================================
#  PENTIGENT · 一键启动脚本（Windows PowerShell）
#  双击 start.bat 或运行 .\run.ps1 即可
#  自动：检测 Go / PostgreSQL / Node → 安装缺失项 → 建库
#        → 构建前端+后端 → 启动服务 → 自动打开浏览器
#  参数：-NoOpen 不自动打开浏览器
# ============================================================

param([switch]$NoOpen, [switch]$NoBuild)
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $root

$host.ui.RawUI.WindowTitle = "PENTIGENT 启动"

function Write-Step($msg) { Write-Output ""; Write-Output "========== $msg ==========" }
function Find-Go {
  $cands = @(
    "C:\Users\Administrator\go-toolchain\go\bin\go.exe",
    "C:\Go\bin\go.exe",
    "C:\Program Files\Go\bin\go.exe"
  )
  foreach ($c in $cands) { if (Test-Path $c) { return $c } }
  $onPath = Get-Command go -ErrorAction SilentlyContinue
  if ($onPath) { return $onPath.Source }
  return $null
}
function Find-Psql {
  $cands = @(
    "C:\Program Files\PostgreSQL\16\bin\psql.exe",
    "C:\Program Files\PostgreSQL\17\bin\psql.exe",
    "C:\Program Files\PostgreSQL\15\bin\psql.exe"
  )
  foreach ($c in $cands) { if (Test-Path $c) { return $c } }
  $onPath = Get-Command psql -ErrorAction SilentlyContinue
  if ($onPath) { return $onPath.Source }
  return $null
}

# ---------- 1. Go ----------
Write-Step "1/5 检查 Go"
$go = Find-Go
if (-not $go) {
  Write-Output "未找到 Go，尝试通过 winget 安装 Go 1.27..."
  winget install --id GoLang.Go --accept-source-agreements --accept-package-agreements --silent | Out-Null
  $go = Find-Go
  if (-not $go) { Write-Output "Go 安装失败，请手动安装后重试：https://go.dev/dl/"; exit 1 }
}
Write-Output "  Go: $go"
$env:Path = (Split-Path $go) + ";" + $env:Path
$env:GOPATH = "C:\Users\Administrator\gopath"
$env:GOFLAGS = "-mod=mod"
& $go version

# ---------- 2. PostgreSQL ----------
Write-Step "2/5 检查 PostgreSQL"
$psql = Find-Psql
if (-not $psql) {
  Write-Output "未找到 PostgreSQL，尝试安装 PostgreSQL 16..."
  winget install --id PostgreSQL.PostgreSQL.16 --accept-source-agreements --accept-package-agreements --silent | Out-Null
  $psql = Find-Psql
  if (-not $psql) { Write-Output "PostgreSQL 安装失败，请手动安装后重试：https://www.postgresql.org/download/windows/"; exit 1 }
}
Write-Output "  psql: $psql"
$pgBin = Split-Path $psql
$env:Path = "$pgBin;" + $env:Path
# 默认本地开发密码（与 config.json 的 dsn 一致：postgres/postgres@127.0.0.1:5432/pentigent）
$env:PGPASSWORD = "postgres"

# 确保服务运行
$svc = Get-Service -Name "postgresql*" -ErrorAction SilentlyContinue | Select-Object -First 1
if ($svc -and $svc.Status -ne "Running") { Start-Service $svc.Name; Start-Sleep -Seconds 3 }
if ($svc) { Write-Output "  服务: $($svc.Name) ($($svc.Status))" }

# 建库（幂等）
Write-Output "  检查数据库 pentigent ..."
$dbExist = & $psql -U postgres -h 127.0.0.1 -t -A -c "SELECT 1 FROM pg_database WHERE datname='pentigent'" 2>$null
if ($LASTEXITCODE -ne 0 -or [string]$dbExist -ne "1") {
  & $psql -U postgres -h 127.0.0.1 -c "CREATE DATABASE pentigent" *> $null
  if ($LASTEXITCODE -eq 0) { Write-Output "  已创建数据库 pentigent" }
  else { Write-Output "  创建数据库失败（检查 postgres 密码是否为 postgres，或改 config.json 的 dsn）" }
} else {
  Write-Output "  数据库已存在"
}

# ---------- 3. Node（仅构建前端需要） ----------
Write-Step "3/5 检查 Node"
$needNode = (Test-Path "$root\web\package.json") -and (-not (Test-Path "$root\web\node_modules"))
if ($needNode) {
  $node = Get-Command node -ErrorAction SilentlyContinue
  if ($node) {
    Write-Output "  node $((& $node.Source --version))"
  } else {
    Write-Output "  未找到 Node，尝试安装..."
    winget install --id OpenJS.NodeJS.LTS --accept-source-agreements --accept-package-agreements --silent | Out-Null
    $env:Path = "C:\Program Files\nodejs;" + $env:Path
  }
} else {
  Write-Output "  前端无需 node（已构建或跳过）"
}

# ---------- 4. 构建 ----------
Write-Step "4/5 构建"
# 前端（web/ 源码变化或首次时）
if (Test-Path "$root\web\package.json") {
  Push-Location "$root\web"
  if (-not (Test-Path node_modules)) { npm install --no-audit --no-fund }
  Write-Output "  [前端] npm run build ..."
  npm run build | Out-Null
  Pop-Location
  if (Test-Path "$root\web\out") {
    Remove-Item "$root\webui\dist" -Recurse -Force -ErrorAction SilentlyContinue
    New-Item -ItemType Directory -Path "$root\webui\dist" -Force | Out-Null
    Copy-Item "$root\web\out\*" "$root\webui\dist" -Recurse -Force
    Write-Output "  [前端] 已内嵌到单二进制"
  }
}
# 后端单二进制
Write-Output "  [后端] go build ..."
& $go build -o "$root\pentigent.exe" ./cmd/pentigent
if ($LASTEXITCODE -ne 0) { Write-Output "  后端构建失败"; exit 1 }
Write-Output "  pentigent.exe 构建完成 ($([math]::Round((Get-Item "$root\pentigent.exe").Length/1MB,1)) MB)"

# ---------- 5. 启动 ----------
Write-Step "5/5 启动服务"
Get-Process -Name pentigent -ErrorAction SilentlyContinue | Stop-Process -Force
Start-Sleep -Seconds 1
Start-Process -FilePath "$root\pentigent.exe" -ArgumentList "config.json" -WorkingDirectory $root -WindowStyle Hidden
Start-Sleep -Seconds 3

$base = "http://127.0.0.1:8080"
try {
  $health = Invoke-RestMethod -Uri "$base/api/health" -TimeoutSec 5
  Write-Output ""
  Write-Output "=============================================="
  Write-Output "  PENTIGENT 已就绪"
  Write-Output "  浏览器打开:  $base"
  Write-Output "  LLM 模式:   $($health.llm)  (mock=$($health.mock))"
  Write-Output "  初始化状态: setup=$($health.setup)"
  Write-Output "=============================================="
  Write-Output ""
  # 自动打开浏览器（-NoOpen 时跳过）
  if (-not $NoOpen) { Start-Process $base }
  Write-Output "常用："
  Write-Output "  在线实测: .\e2e-test.ps1"
  Write-Output "  看日志:   logs\pentigent.log"
  Write-Output "  停止服务: Stop-Process -Name pentigent"
  if (-not $NoOpen) {
    Write-Output ""
    Write-Host "服务已在后台运行 —— 本窗口可关，浏览器已打开 http://127.0.0.1:8080" -ForegroundColor Green
  }
} catch {
  Write-Output "服务启动失败：$($_.Exception.Message)"
  Write-Output "请查看日志 logs\pentigent.log"
  exit 1
}