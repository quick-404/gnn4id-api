import requests
import time
import random
from datetime import datetime

API_URL = 'http://localhost:5000/api/attack/detect'

print('=' * 60)
print('GNN4ID 实时攻击检测')
print('=' * 60)
print('每8秒发送一次模拟攻击...')
print('按 Ctrl+C 停止')
print('=' * 60)
print()

attack_templates = [
    {'name': 'DDoS攻击', 'bytes_rate': random.randint(1000000, 5000000), 'packet_count': random.randint(5000, 20000), 'unique_ports': random.randint(1, 5)},
    {'name': '端口扫描', 'unique_ports': random.randint(50, 100), 'packet_count': random.randint(100, 500)},
    {'name': '暴力破解SSH', 'dst_port': 22, 'failed_logins': random.randint(5, 20), 'packet_count': random.randint(50, 200)},
    {'name': 'SQL注入', 'dst_port': 80, 'has_payload': True, 'suspicious_patterns': random.randint(1, 3)},
    {'name': 'XSS攻击', 'dst_port': 8080, 'has_payload': True, 'suspicious_patterns': 1},
    {'name': '正常流量', 'bytes_rate': random.randint(1000, 50000), 'packet_count': random.randint(10, 100), 'unique_ports': random.randint(1, 3)},
    {'name': 'DoS攻击', 'bytes_rate': random.randint(500000, 1000000), 'packet_count': random.randint(1000, 5000)},
]

count = 0
while count < 10:
    attack = random.choice(attack_templates)
    attack['bytes'] = random.randint(100, 100000)
    
    try:
        r = requests.post(API_URL, json=attack, timeout=2)
        if r.status_code == 200:
            result = r.json()
            detected = '[ATTACK]' if result.get('detected') else '[Normal]'
            conf = result.get('confidence', 0)
            print(f'{detected} [{datetime.now().strftime("%H:%M:%S")}] {attack["name"]:12} -> {result.get("attackName", "正常"):10} ({conf:.0%})')
    except Exception as e:
        print(f'[ERROR] {e}')
    
    count += 1
    if count < 10:
        time.sleep(3)

print()
print('=' * 60)
print('演示完成！查看微信小程序中的攻击检测页面')
print('=' * 60)
input('按回车键退出...')
