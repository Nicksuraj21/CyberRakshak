@echo off
title Cyber Rakshak IDS Server
echo Starting Cyber Rakshak IDS Server...
python mainapp.py 2>nul || py mainapp.py 2>nul || "C:\Users\sk740\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe" mainapp.py || "C:\Users\sk740\AppData\Local\Programs\Python\Python313\python.exe" mainapp.py
pause
