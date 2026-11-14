$ErrorActionPreference = 'Stop'
$labRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
$tbPython = Join-Path $labRoot 'runtime\tensorboard\venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $tbPython)) { throw 'Run tools\tensorboard\setup.ps1 first' }
& $tbPython -B (Join-Path $PSScriptRoot 'serve.py') --open
