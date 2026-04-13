@echo off
chcp 65001 >nul
title GNN4ID-FlowAnalyzer API 服务

echo ================================================
echo   GNN4ID-FlowAnalyzer 后端服务启动中...
echo ================================================
echo.

cd /d "%~dp0"

echo [1/3] 检查Python环境...
python --version >nul 2>&1
if errorlevel 1 (
    echo [错误] 未找到Python，请先安装Python 3.6+
    pause
    exit /b 1
)

echo [2/3] 安装依赖...
pip install flask flask-cors -q
if errorlevel 1 (
    echo [警告] 部分依赖安装失败，继续尝试启动...
)

echo [3/3] 启动API服务...
echo.
echo 服务地址: http://localhost:5000
echo 按 Ctrl+C 停止服务
echo.
echo ================================================

python api_server.py

pause
