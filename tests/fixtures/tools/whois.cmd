@echo off
if defined PYTHON (
    "%PYTHON%" "%~dp0fake_tool.py" whois %*
) else (
    python "%~dp0fake_tool.py" whois %*
)
