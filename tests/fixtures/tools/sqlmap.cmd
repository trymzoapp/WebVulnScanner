@echo off
if defined PYTHON (
    "%PYTHON%" "%~dp0fake_tool.py" sqlmap %*
) else (
    python "%~dp0fake_tool.py" sqlmap %*
)
