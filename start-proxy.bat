@echo off
title Dhan/Yahoo Proxy Server
echo Checking if Node.js is installed...
node -v >nul 2>&1
if %errorlevel% neq 0 (
    echo Error: Node.js is not installed or not in PATH. Please install Node.js from https://nodejs.org/
    pause
    exit /b 1
)

echo Starting Dhan/Yahoo Proxy Server...
echo --------------------------------------------------
node dhan-proxy.js
if %errorlevel% neq 0 (
    echo.
    echo Proxy server stopped with an error.
    pause
)
