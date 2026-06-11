@echo off
setlocal
title Qoder Batch Login for 9router

echo.
echo  ===================================================
echo     Qoder Auto-Login for 9router - Batch Mode
echo  ===================================================
echo.

python "%~dp0qoder_autologin.py" --batch "%~dp0accounts.txt" --interactive %*

echo.
echo  Script finished. Window will stay open — close it manually.
echo.
cmd /k

