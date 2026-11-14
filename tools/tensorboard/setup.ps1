$ErrorActionPreference = 'Stop'
$labRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
$tbPython = Join-Path $labRoot 'runtime\tensorboard\venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $tbPython)) {
    python -m venv (Join-Path $labRoot 'runtime\tensorboard\venv')
    if ($LASTEXITCODE -ne 0) { throw 'Cannot create TensorBoard venv' }
}
& $tbPython -m pip install --only-binary=:all: -r (Join-Path $PSScriptRoot 'requirements.txt')
if ($LASTEXITCODE -ne 0) { throw 'TensorBoard dependency installation failed' }
& $tbPython -m pip check
if ($LASTEXITCODE -ne 0) { throw 'TensorBoard dependency check failed' }
Write-Output 'TensorBoard ready. Open it from the dashboard, or run tools\tensorboard\start.ps1.'
