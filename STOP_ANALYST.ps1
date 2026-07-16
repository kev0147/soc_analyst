$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$statePath = Join-Path $root "backend\.runtime\local_processes.json"
if (-not (Test-Path $statePath)) {
    Write-Host "Aucun lancement local enregistre."
    exit 0
}

$state = Get-Content $statePath -Raw | ConvertFrom-Json
$launchedAt = [DateTime]::Parse($state.launched_at).ToUniversalTime()
foreach ($processId in @($state.backend_pid, $state.worker_pid, $state.frontend_pid)) {
    $process = Get-Process -Id $processId -ErrorAction SilentlyContinue
    if ($process -and $process.StartTime.ToUniversalTime() -ge $launchedAt.AddSeconds(-5)) {
        taskkill.exe /PID $processId /T /F | Out-Null
    }
}
Remove-Item -LiteralPath $statePath -Force
Write-Host "Processus SOC Analyst arretes."
