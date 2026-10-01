@echo off
if defined PYTHON (
    "%PYTHON%" "%~dp0fake_tool.py" gobuster %*
) else (
    python "%~dp0fake_tool.py" gobuster %*
)
