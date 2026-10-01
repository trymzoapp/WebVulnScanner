@echo off
if defined PYTHON (
    "%PYTHON%" "%~dp0fake_tool.py" wappalyzer %*
) else (
    python "%~dp0fake_tool.py" wappalyzer %*
)
