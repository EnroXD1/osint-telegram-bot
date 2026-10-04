$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot
if (-not (Test-Path -LiteralPath '.venv\Scripts\python.exe')) {
    throw 'Run setup.ps1 first.'
}
& '.\.venv\Scripts\python.exe' -m osint_bot
exit $LASTEXITCODE
