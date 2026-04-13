"""
网络流量采集器 - Network Traffic Collector
用于捕获真实网络流量并发送检测
"""

import socket
import threading
import time
import random
import json
from datetime import datetime

try:
    from scapy.all import *
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("[WARNING] Scapy未安装，将使用模拟模式")

import requests

# 配置
API_URL = "http://localhost:5000/api"
INTERFACE = None  # None表示所有网卡，或指定如"eth0"
PACKET_COUNT = 0  # 统计抓包数量
STOP_FLAG = False

def extract_features_from_packet(pkt):
    """
    从数据包中提取特征（模拟CICIDS2017特征格式）
    """
    features = {
        'timestamp': datetime.now().isoformat(),
        'src_port': 0,
        'dst_port': 0,
        'protocol': 'Unknown',
        'packet_count': 1,
        'bytes_rate': 0,
        'flow_duration': 0,
        'unique_ports': 0,
        'has_payload': False,
        'suspicious_patterns': 0,
        'failed_logins': 0
    }
    
    if IP in pkt:
        features['src_ip'] = pkt[IP].src
        features['dst_ip'] = pkt[IP].dst
        
        # TCP/UDP端口
        if TCP in pkt:
            features['src_port'] = pkt[TCP].sport
            features['dst_port'] = pkt[TCP].dport
            features['protocol'] = 'TCP'
            features['has_payload'] = len(pkt[TCP].payload) > 0
            
            # 检测可疑模式
            if Raw in pkt:
                payload = str(pkt[Raw].load)
                if any(x in payload.lower() for x in ['select', 'union', 'drop', 'script', '<img']):
                    features['suspicious_patterns'] = 1
                    
        elif UDP in pkt:
            features['src_port'] = pkt[UDP].sport
            features['dst_port'] = pkt[UDP].dport
            features['protocol'] = 'UDP'
            
        elif ICMP in pkt:
            features['protocol'] = 'ICMP'
            
    features['bytes'] = len(pkt)
    
    return features


def packet_callback(pkt):
    """数据包回调函数"""
    global PACKET_COUNT
    
    if IP in pkt:
        PACKET_COUNT += 1
        features = extract_features_from_packet(pkt)
        
        # 发送到后端（每10个包发送一次）
        if PACKET_COUNT % 10 == 0:
            send_to_api(features)
        
        # 打印信息
        if PACKET_COUNT % 50 == 0:
            print(f"[{datetime.now().strftime('%H:%M:%S')}] 已捕获 {PACKET_COUNT} 个数据包")


def send_to_api(features):
    """发送特征到后端API"""
    try:
        response = requests.post(
            f"{API_URL}/attack/detect",
            json=features,
            timeout=2
        )
        if response.status_code == 200:
            result = response.json()
            if result.get('detected'):
                print(f"[!] 检测到攻击: {result.get('attackName')} ({result.get('confidence')})")
    except requests.exceptions.RequestException as e:
        pass  # 静默处理网络错误


def capture_realtime():
    """实时抓包模式"""
    if not SCAPY_AVAILABLE:
        print("[ERROR] Scapy未安装，无法进行实时抓包")
        return
    
    print("=" * 50)
    print("🔍 实时网络流量采集器")
    print("=" * 50)
    print(f"目标API: {API_URL}")
    print(f"网卡: {INTERFACE or '所有网卡'}")
    print("按 Ctrl+C 停止")
    print("=" * 50)
    
    try:
        sniff(iface=INTERFACE, prn=packet_callback, store=False, timeout=60)
    except KeyboardInterrupt:
        print("\n[INFO] 停止抓包")
    except Exception as e:
        print(f"[ERROR] {e}")


def simulate_attacks():
    """模拟攻击流量（用于演示）"""
    print("=" * 50)
    print("⚠️  模拟攻击模式")
    print("=" * 50)
    print("将模拟各种网络攻击，触发真实检测...")
    print("按 Ctrl+C 停止")
    print("=" * 50)
    
    attack_templates = [
        # 端口扫描模拟
        {
            'name': '端口扫描',
            'src_port': random.randint(40000, 60000),
            'unique_ports': random.randint(50, 100),
            'packet_count': random.randint(100, 500),
            'suspicious_patterns': 0,
            'expected': '侦察攻击'
        },
        # DDoS攻击模拟
        {
            'name': 'DDoS攻击',
            'src_port': random.randint(40000, 60000),
            'bytes_rate': random.randint(1000000, 5000000),
            'packet_count': random.randint(5000, 20000),
            'unique_ports': random.randint(1, 5),
            'expected': 'DDoS攻击'
        },
        # 暴力破解模拟
        {
            'name': '暴力破解SSH',
            'src_port': 22,
            'dst_port': 22,
            'failed_logins': random.randint(5, 20),
            'packet_count': random.randint(50, 200),
            'expected': '暴力破解'
        },
        # Web攻击模拟
        {
            'name': 'SQL注入',
            'src_port': random.randint(40000, 60000),
            'dst_port': 80,
            'has_payload': True,
            'suspicious_patterns': random.randint(1, 3),
            'expected': 'Web攻击'
        },
        # 正常流量
        {
            'name': '正常流量',
            'src_port': random.randint(40000, 60000),
            'bytes_rate': random.randint(1000, 50000),
            'packet_count': random.randint(10, 100),
            'unique_ports': random.randint(1, 3),
            'expected': '正常流量'
        }
    ]
    
    interval = 8  # 每8秒模拟一次攻击
    
    while not STOP_FLAG:
        attack = random.choice(attack_templates)
        attack['timestamp'] = datetime.now().isoformat()
        attack['bytes'] = random.randint(100, 100000)
        
        try:
            response = requests.post(
                f"{API_URL}/attack/detect",
                json=attack,
                timeout=2
            )
            
            if response.status_code == 200:
                result = response.json()
                status = "✅" if result.get('detected') else "✓"
                print(f"\n{status} [{datetime.now().strftime('%H:%M:%S')}] 发送: {attack['name']}")
                print(f"   预期: {attack['expected']} | 检测: {result.get('attackName', '正常')} | "
                      f"置信度: {result.get('confidence', 0):.2f} | 等级: {result.get('level', 'none')}")
                
        except requests.exceptions.RequestException as e:
            print(f"[ERROR] 无法连接后端API: {e}")
        
        time.sleep(interval)


def menu():
    """显示菜单"""
    print("\n" + "=" * 50)
    print("🛡️  GNN4ID 网络流量采集器")
    print("=" * 50)
    print("1. 实时抓包模式（需要Scapy）")
    print("2. 模拟攻击模式（推荐，用于演示）")
    print("3. 退出")
    print("=" * 50)
    
    choice = input("请选择 (1/2/3): ").strip()
    
    if choice == '1':
        capture_realtime()
    elif choice == '2':
        try:
            simulate_attacks()
        except KeyboardInterrupt:
            global STOP_FLAG
            STOP_FLAG = True
            print("\n[INFO] 已停止模拟")
    elif choice == '3':
        print("再见!")
        exit()
    else:
        print("无效选择")


if __name__ == "__main__":
    print("\n" + "=" * 50)
    print("🛡️  GNN4ID-FlowAnalyzer 流量采集器")
    print("=" * 50)
    
    # 检查API连接
    try:
        response = requests.get(f"{API_URL}/health", timeout=2)
        if response.status_code == 200:
            print("✅ 后端API连接正常")
        else:
            print("⚠️  后端API响应异常")
    except:
        print("⚠️  无法连接到后端API，请确保 api_server.py 已启动")
        print(f"   预期地址: {API_URL}")
    
    print("=" * 50)
    
    menu()
