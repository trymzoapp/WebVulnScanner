@echo off
if defined PYTHON (
    "%PYTHON%" "%~dp0fake_tool.py" subfinder %*
) else (
    python "%~dp0fake_tool.py" subfinder %*
)
