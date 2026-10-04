$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot
$taskPython = Get-Command py -ErrorAction SilentlyContinue
if ($taskPython) {
    & $taskPython.Source -3 -m venv .venv
} else {
    $taskPython = Get-Command python -ErrorAction SilentlyContinue
    if ($taskPython) {
        & $taskPython.Source -m venv .venv
    } else {
        $taskBundledPython = Join-Path $env:USERPROFILE '.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe'
        if (-not (Test-Path -LiteralPath $taskBundledPython)) {
            throw 'Install Python 3.12 first: https://www.python.org/downloads/'
        }
        & $taskBundledPython -m venv .venv
    }
}
if ($LASTEXITCODE -ne 0) { throw 'Could not create .venv.' }
& '.\.venv\Scripts\python.exe' -m pip install --disable-pip-version-check -r requirements.txt
if ($LASTEXITCODE -ne 0) { throw 'Dependency installation failed.' }
if (-not (Test-Path -LiteralPath '.env')) {
    Copy-Item -LiteralPath '.env.example' -Destination '.env'
}
Write-Output 'Ready. Set BOT_TOKEN in .env, then run start.ps1.'
