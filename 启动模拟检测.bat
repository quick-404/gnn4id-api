@echo off
chcp 65001 >nul
title GNN4ID 流量采集器 - 模拟攻击模式

echo.
echo ================================================
echo    🛡️  GNN4ID 流量采集器
echo    模拟攻击模式 - 实时检测演示
echo ================================================
echo.

cd /d "%~dp0"

echo [1/2] 检查后端连接...
python -c "import requests; r=requests.get('http://localhost:5000/api/health', timeout=3); print('  ✅ 后端API正常' if r.status_code==200 else '  ⚠️ 后端异常')" 2>nul
if errorlevel 1 (
    echo  ⚠️  无法连接后端API
    echo  请先启动 api_server.py
    echo.
    pause
    exit /b 1
)

echo [2/2] 启动模拟攻击检测...
echo.
echo ================================================
echo  按 Ctrl+C 停止检测
echo ================================================
echo.

python -c "
import requests
import time
import random
from datetime import datetime

API_URL = 'http://localhost:5000/api/attack/detect'

attack_templates = [
    {'name': 'DDoS攻击', 'bytes_rate': random.randint(1000000, 5000000), 'packet_count': random.randint(5000, 20000), 'unique_ports': random.randint(1, 5), 'expected': 'DDoS攻击'},
    {'name': '端口扫描', 'unique_ports': random.randint(50, 100), 'packet_count': random.randint(100, 500), 'expected': '侦察攻击'},
    {'name': '暴力破解SSH', 'dst_port': 22, 'failed_logins': random.randint(5, 20), 'packet_count': random.randint(50, 200), 'expected': '暴力破解'},
    {'name': 'SQL注入', 'dst_port': 80, 'has_payload': True, 'suspicious_patterns': random.randint(1, 3), 'expected': 'Web攻击'},
    {'name': 'XSS攻击', 'dst_port': 8080, 'has_payload': True, 'suspicious_patterns': 1, 'expected': 'Web攻击'},
    {'name': '正常流量', 'bytes_rate': random.randint(1000, 50000), 'packet_count': random.randint(10, 100), 'unique_ports': random.randint(1, 3), 'expected': '正常流量'},
    {'name': 'DoS攻击', 'bytes_rate': random.randint(500000, 1000000), 'packet_count': random.randint(1000, 5000), 'expected': 'DoS攻击'},
]

print('开始模拟攻击检测，每8秒发送一次...')
print()

while True:
    attack = random.choice(attack_templates)
    attack['bytes'] = random.randint(100, 100000)
    
    try:
        r = requests.post(API_URL, json=attack, timeout=2)
        if r.status_code == 200:
            result = r.json()
            detected = '⚠️' if result.get('detected') else '✅'
            print(f'{detected} [{datetime.now().strftime(\"%H:%M:%S\")}] {attack[\"name\"]:12} -> {result.get(\"attackName\", \"正常\"):10} (置信度: {result.get(\"confidence\", 0):.2f})')
    except:
        pass
    
    time.sleep(8)
"

pause
