@echo off
title Delzar Certification Academy
cd /d "%~dp0.."
where py >nul 2>nul && (py -3 main.py web) || (python main.py web)
if errorlevel 1 (echo. & echo Python 3.10+ is required: https://www.python.org/downloads/ & pause)
