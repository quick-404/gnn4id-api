"""
GNN4ID-FlowAnalyzer 后端API服务（简化版）
网络入侵检测系统 - 演示版
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
from datetime import datetime
import random
import os

app = Flask(__name__)
CORS(app)

# 攻击类型映射
ATTACK_TYPES = {
    0: {'name': '正常流量', 'level': 'none', 'description': '合法的网络流量'},
    1: {'name': 'Web攻击', 'level': 'high', 'description': 'SQL注入、XSS等Web应用攻击'},
    2: {'name': '欺骗攻击', 'level': 'medium', 'description': 'ARP欺骗、IP欺骗等'},
    3: {'name': '侦察攻击', 'level': 'medium', 'description': '端口扫描、网络踩点'},
    4: {'name': 'Mirai', 'level': 'high', 'description': 'IoT僵尸网络攻击'},
    5: {'name': 'DoS攻击', 'level': 'high', 'description': '拒绝服务攻击'},
    6: {'name': 'DDoS攻击', 'level': 'high', 'description': '分布式拒绝服务攻击'},
    7: {'name': '暴力破解', 'level': 'medium', 'description': '密码暴力猜测攻击'}
}

# 统计数据
stats = {
    'total': 0,
    'attacks': 0,
    'normal': 0,
    'recent_alerts': []
}


def detect_attack(flow_data):
    """
    模拟检测逻辑
    实际项目中这里会调用GNN模型
    """
    # 根据流量特征模拟检测
    score = random.random()
    
    if score < 0.15:
        attack_type = random.randint(1, 7)
    else:
        attack_type = 0
    
    confidence = random.uniform(0.85, 0.99)
    
    return attack_type, confidence


@app.route('/api/health')
def health():
    """健康检查"""
    return jsonify({'status': 'ok', 'timestamp': datetime.now().isoformat()})


@app.route('/api/stats')
def get_stats():
    """获取统计信息"""
    return jsonify({
        'total': stats['total'],
        'attacks': stats['attacks'],
        'normal': stats['normal'],
        'attackRate': round(stats['attacks'] / max(stats['total'], 1) * 100, 1),
        'timestamp': datetime.now().isoformat()
    })


@app.route('/api/traffic/list')
def get_traffic_list():
    """获取流量列表"""
    page = int(request.args.get('page', 1))
    pageSize = int(request.args.get('pageSize', 20))
    
    flows = []
    for i in range(pageSize):
        attack_type, confidence = detect_attack({})
        attack_info = ATTACK_TYPES[attack_type]
        
        flows.append({
            'id': (page - 1) * pageSize + i + 1,
            'src_ip': f'192.168.{random.randint(1,10)}.{random.randint(1,254)}',
            'dst_ip': f'10.0.{random.randint(1,10)}.{random.randint(1,254)}',
            'protocol': random.choice(['TCP', 'UDP', 'HTTP', 'HTTPS']),
            'src_port': random.randint(1024, 65535),
            'dst_port': random.choice([80, 443, 22, 3306, 8080]),
            'bytes': random.randint(100, 100000),
            'packets': random.randint(1, 100),
            'attack_type': attack_info['name'],
            'confidence': round(confidence * 100, 1),
            'level': attack_info['level'],
            'timestamp': datetime.now().isoformat()
        })
        
        stats['total'] += 1
        if attack_type > 0:
            stats['attacks'] += 1
        else:
            stats['normal'] += 1
    
    return jsonify({
        'list': flows,
        'total': stats['total'],
        'page': page,
        'pageSize': pageSize
    })


@app.route('/api/attack/list')
def get_attack_list():
    """获取攻击列表"""
    page = int(request.args.get('page', 1))
    pageSize = int(request.args.get('pageSize', 20))
    
    attacks = []
    for i in range(pageSize):
        attack_type = random.randint(1, 7)
        attack_info = ATTACK_TYPES[attack_type]
        
        attacks.append({
            'id': (page - 1) * pageSize + i + 1,
            'type': attack_info['name'],
            'level': attack_info['level'],
            'src_ip': f'192.168.{random.randint(1,10)}.{random.randint(1,254)}',
            'dst_ip': f'10.0.{random.randint(1,10)}.{random.randint(1,254)}',
            'confidence': round(random.uniform(85, 99), 1),
            'time': f"{random.randint(1, 60)}分钟前",
            'description': attack_info['description']
        })
    
    return jsonify({
        'list': attacks,
        'total': stats['attacks'],
        'page': page,
        'pageSize': pageSize
    })


@app.route('/api/attack/detect', methods=['POST'])
def detect():
    """单条流量检测"""
    flow_data = request.json or {}
    
    attack_type, confidence = detect_attack(flow_data)
    attack_info = ATTACK_TYPES[attack_type]
    
    stats['total'] += 1
    if attack_type > 0:
        stats['attacks'] += 1
    else:
        stats['normal'] += 1
    
    return jsonify({
        'is_attack': attack_type > 0,
        'attack_type': attack_info['name'],
        'confidence': round(confidence * 100, 1),
        'level': attack_info['level'],
        'description': attack_info['description']
    })


@app.route('/api/topology')
def get_topology():
    """获取网络拓扑"""
    nodes = [
        {'id': 'firewall', 'type': 'firewall', 'name': '防火墙', 'x': 200, 'y': 50, 'status': 'normal'},
        {'id': 'router', 'type': 'router', 'name': '路由器', 'x': 200, 'y': 150, 'status': 'normal'},
        {'id': 'switch', 'type': 'switch', 'name': '核心交换机', 'x': 200, 'y': 250, 'status': 'normal'},
        {'id': 'server1', 'type': 'server', 'name': 'Web服务器', 'x': 100, 'y': 350, 'status': 'normal'},
        {'id': 'server2', 'type': 'server', 'name': '数据库服务器', 'x': 200, 'y': 350, 'status': 'normal'},
        {'id': 'server3', 'type': 'server', 'name': '文件服务器', 'x': 300, 'y': 350, 'status': 'warning'},
        {'id': 'workstation1', 'type': 'workstation', 'name': '工作站1', 'x': 50, 'y': 450, 'status': 'normal'},
        {'id': 'workstation2', 'type': 'workstation', 'name': '工作站2', 'x': 150, 'y': 450, 'status': 'attack'},
        {'id': 'internet', 'type': 'internet', 'name': '互联网', 'x': 200, 'y': -50, 'status': 'warning'}
    ]
    
    edges = [
        {'source': 'internet', 'target': 'firewall', 'type': 'WAN'},
        {'source': 'firewall', 'target': 'router', 'type': 'LAN'},
        {'source': 'router', 'target': 'switch', 'type': 'LAN'},
        {'source': 'switch', 'target': 'server1', 'type': 'SERVER'},
        {'source': 'switch', 'target': 'server2', 'type': 'SERVER'},
        {'source': 'switch', 'target': 'server3', 'type': 'SERVER'},
        {'source': 'switch', 'target': 'workstation1', 'type': 'CLIENT'},
        {'source': 'switch', 'target': 'workstation2', 'type': 'CLIENT'}
    ]
    
    return jsonify({'nodes': nodes, 'edges': edges})


@app.route('/api/monitor/metrics')
def get_metrics():
    """获取监控指标"""
    return jsonify({
        'throughput': round(random.uniform(200, 400), 1),
        'throughputUnit': 'Mbps',
        'connections': random.randint(500, 2000),
        'alerts': stats['attacks'],
        'accuracy': round(random.uniform(95.0, 98.5), 1),
        'latency': round(random.uniform(1, 10), 1),
        'timestamp': datetime.now().isoformat()
    })


@app.route('/api/alerts/recent')
def get_recent_alerts():
    """获取最近告警"""
    alerts = []
    for i in range(10):
        attack_type = random.randint(1, 7)
        attack_info = ATTACK_TYPES[attack_type]
        
        alerts.append({
            'id': i + 1,
            'type': attack_info['name'],
            'level': attack_info['level'],
            'source': f'192.168.{random.randint(1,10)}.{random.randint(1,254)}',
            'target': f'10.0.{random.randint(1,10)}.{random.randint(1,254)}',
            'time': f"{random.randint(1, 60)}分钟前",
            'message': f"检测到{attack_info['name']}，风险等级: {attack_info['level']}"
        })
    
    return jsonify({'alerts': alerts})


if __name__ == '__main__':
    print("\n" + "="*50)
    print("GNN4ID-FlowAnalyzer API 服务")
    print("="*50)
    # Railway 会设置 PORT 环境变量
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
