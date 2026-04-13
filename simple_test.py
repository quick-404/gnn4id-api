import requests, time, random, sys
from datetime import datetime

API = "http://localhost:5000/api/attack/detect"
attacks = [
    {"name": "DDoS攻击", "bytes_rate": 2000000, "packet_count": 8000, "unique_ports": 3},
    {"name": "端口扫描", "unique_ports": 75, "packet_count": 300},
    {"name": "暴力破解", "dst_port": 22, "failed_logins": 8, "packet_count": 100},
    {"name": "SQL注入", "dst_port": 80, "has_payload": True, "suspicious_patterns": 2},
    {"name": "正常流量", "bytes_rate": 5000, "packet_count": 50, "unique_ports": 2},
]

print("=" * 50)
print("GNN4ID 实时攻击检测演示")
print("=" * 50)

for i in range(5):
    a = random.choice(attacks)
    a["bytes"] = random.randint(1000, 50000)
    try:
        r = requests.post(API, json=a, timeout=2)
        if r.status_code == 200:
            res = r.json()
            status = "[ATTACK]" if res.get("detected") else "[Normal]"
            conf = res.get("confidence", 0)
            print(status + " " + a["name"] + " -> " + res.get("attackName", "") + " (" + str(int(conf*100)) + "%)")
    except Exception as e:
        print("Error: " + str(e))
    if i < 4:
        time.sleep(2)

print("=" * 50)
print("演示完成!")
