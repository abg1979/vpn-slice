@echo off
set script_dir=%~dp0
set script_name=%~nx0
for /f "tokens=2 delims=[]" %%H in  ('dir /al %script_dir% ^| findstr /i /c:"%script_name%"') do (
    set work_dir=%%H
)
if defined work_dir (
    for %%a in ("%work_dir%") do set "work_dir=%%~dpa"
) else (
    set work_dir=%script_dir%
)
set python_venv_dir=%work_dir%.venv
call %python_venv_dir%/scripts/activate.bat
set current_dir=%cd%
cd %work_dir%
python -m vpn_slice __main__ %*
call %python_venv_dir%/scripts/deactivate.bat
cd %current_dir%
