$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $root

$pythonCandidates = @(
    (Join-Path $root ".venv\Scripts\python.exe"),
    (Join-Path $root "backend\env\Scripts\python.exe"),
    (Join-Path $root "env\Scripts\python.exe")
)
$python = $pythonCandidates | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $python) {
    throw "Environnement Python introuvable. Cree .venv puis installe backend\requirements.txt."
}

$npmCommand = Get-Command npm.cmd -ErrorAction SilentlyContinue
if (-not $npmCommand) {
    throw "npm est introuvable. Installe Node.js avant de lancer l'application."
}
if (-not (Test-Path (Join-Path $root "frontend\node_modules"))) {
    throw "Dependances frontend absentes. Execute npm ci dans le dossier frontend."
}

$runtime = Join-Path $root "backend\.runtime"
New-Item -ItemType Directory -Path $runtime -Force | Out-Null
$migrationLog = Join-Path $runtime "migration.log"

& $python "backend\manage.py" migrate --noinput 2>&1 | Tee-Object -FilePath $migrationLog
if ($LASTEXITCODE -ne 0) {
    throw "La migration de la base a echoue. Consulte backend\.runtime\migration.log."
}

$backend = Start-Process -FilePath $python `
    -ArgumentList @("backend\manage.py", "runserver", "127.0.0.1:8000", "--noreload") `
    -WorkingDirectory $root -WindowStyle Hidden -PassThru `
    -RedirectStandardOutput (Join-Path $runtime "backend.out.log") `
    -RedirectStandardError (Join-Path $runtime "backend.err.log")

$worker = Start-Process -FilePath $python `
    -ArgumentList @("backend\manage.py", "run_background_jobs") `
    -WorkingDirectory $root -WindowStyle Hidden -PassThru `
    -RedirectStandardOutput (Join-Path $runtime "worker.out.log") `
    -RedirectStandardError (Join-Path $runtime "worker.err.log")

$frontend = Start-Process -FilePath $npmCommand.Source `
    -ArgumentList @("start") -WorkingDirectory (Join-Path $root "frontend") `
    -WindowStyle Hidden -PassThru `
    -RedirectStandardOutput (Join-Path $runtime "frontend.out.log") `
    -RedirectStandardError (Join-Path $runtime "frontend.err.log")

@{
    launched_at = (Get-Date).ToUniversalTime().ToString("o")
    backend_pid = $backend.Id
    worker_pid = $worker.Id
    frontend_pid = $frontend.Id
} | ConvertTo-Json | Set-Content -Path (Join-Path $runtime "local_processes.json") -Encoding UTF8

Start-Sleep -Seconds 3
Start-Process "http://localhost:4200"
Write-Host "SOC Analyst demarre. Frontend: http://localhost:4200"
