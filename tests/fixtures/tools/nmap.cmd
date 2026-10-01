@echo off
if defined PYTHON (
    "%PYTHON%" "%~dp0fake_tool.py" nmap %*
) else (
    python "%~dp0fake_tool.py" nmap %*
)
