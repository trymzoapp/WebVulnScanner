@echo off
if defined PYTHON (
    "%PYTHON%" "%~dp0fake_tool.py" dirsearch %*
) else (
    python "%~dp0fake_tool.py" dirsearch %*
)
