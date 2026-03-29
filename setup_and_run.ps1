param(
  [Parameter(Mandatory=$false)]
  [string]$ProjectDir = "$(Split-Path -Parent $MyInvocation.MyCommand.Path)\VSH_Project_MVP",

  [switch]$SkipInstall,
  [switch]$RunVsCodeExtension
)

$ErrorActionPreference = "Stop"

function Require-Command([string]$name, [string]$hint) {
  if (-not (Get-Command $name -ErrorAction SilentlyContinue)) {
    Write-Host "[VSH] ERROR: '$name' not found. $hint" -ForegroundColor Red
    exit 1
  }
}

$ProjectDir = [System.IO.Path]::GetFullPath($ProjectDir)
$DesktopDir = Join-Path $ProjectDir "vsh_desktop"
$VsCodeDir = Join-Path $ProjectDir "vsh_vscode"
$VenvDir = Join-Path $ProjectDir ".venv"
$PythonExe = Join-Path $VenvDir "Scripts\python.exe"
$ApiStdoutLog = Join-Path $ProjectDir ".vsh_api_stdout.log"
$ApiStderrLog = Join-Path $ProjectDir ".vsh_api_stderr.log"

if ($ProjectDir -like "*OneDrive*") {
  Write-Host "[VSH] WARNING: OneDrive 경로에서는 npm/electron EBUSY, EPERM이 발생할 수 있습니다." -ForegroundColor Yellow
  Write-Host "[VSH] 권장 경로 예시: C:\VSH"
}

if (-not (Test-Path (Join-Path $ProjectDir "requirements.txt"))) {
  Write-Host "[VSH] ERROR: requirements.txt not found in $ProjectDir" -ForegroundColor Red
  exit 1
}

Require-Command python "Install Python 3.12+ and add it to PATH."
Require-Command npm "Install Node.js 20+ and add npm to PATH."

Push-Location $ProjectDir
$apiProc = $null
try {
  if (-not (Test-Path $VenvDir)) {
    Write-Host "[VSH] Creating Python virtual environment..."
    python -m venv "$VenvDir"
  }

  if (-not (Test-Path $PythonExe)) {
    throw "Python executable not found in virtualenv: $PythonExe"
  }

  if (-not $SkipInstall) {
    Write-Host "[VSH] Upgrading pip..."
    & "$PythonExe" -m pip install --upgrade pip

    Write-Host "[VSH] Installing Python dependencies..."
    & "$PythonExe" -m pip install -r requirements.txt

    Write-Host "[VSH] Installing Desktop dependencies..."
    Push-Location $DesktopDir
    npm install
    Pop-Location

    if ($RunVsCodeExtension) {
      Write-Host "[VSH] Installing VS Code extension dependencies..."
      Push-Location $VsCodeDir
      npm install
      npm run compile
      Pop-Location
    }
  }

  Write-Host "[VSH] Starting FastAPI server (http://127.0.0.1:3000)..."
  if (Test-Path $ApiStdoutLog) { Remove-Item $ApiStdoutLog -Force }
  if (Test-Path $ApiStderrLog) { Remove-Item $ApiStderrLog -Force }
  $apiProc = Start-Process -FilePath "$PythonExe" -ArgumentList @("-m","uvicorn","vsh_api.main:app","--host","127.0.0.1","--port","3000") -WorkingDirectory $ProjectDir -PassThru -WindowStyle Normal -RedirectStandardOutput $ApiStdoutLog -RedirectStandardError $ApiStderrLog

  Start-Sleep -Seconds 2
  try {
    $health = Invoke-WebRequest -UseBasicParsing -Uri "http://127.0.0.1:3000/health" -TimeoutSec 3
    Write-Host "[VSH] API health check: $($health.StatusCode)"
  } catch {
    Write-Host "[VSH] WARNING: API health check failed. Check logs:" -ForegroundColor Yellow
    Write-Host " - $ApiStdoutLog"
    Write-Host " - $ApiStderrLog"
  }

  Write-Host "[VSH] Starting Desktop app..."
  Push-Location $DesktopDir
  $env:VSH_AUTO_START_API = "false"
  npm run electron-dev
  Pop-Location
}
catch {
  Write-Host "[VSH] ERROR: $($_.Exception.Message)" -ForegroundColor Red
  Write-Host "[VSH] Logs (if any):"
  Write-Host " - $ApiStdoutLog"
  Write-Host " - $ApiStderrLog"
  exit 1
}
finally {
  Pop-Location
  if ($apiProc -and -not $apiProc.HasExited) {
    Write-Host "[VSH] Stopping API server (PID=$($apiProc.Id))"
    Stop-Process -Id $apiProc.Id -Force -ErrorAction SilentlyContinue
  }
}
