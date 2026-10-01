@echo off
if defined PYTHON (
    "%PYTHON%" "%~dp0fake_tool.py" wpscan %*
) else (
    python "%~dp0fake_tool.py" wpscan %*
)
