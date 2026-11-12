@echo off
cd /d "%~dp0.."
python -B dashboard\app.py --open
pause
