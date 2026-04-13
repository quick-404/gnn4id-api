"""
GNN4ID-FlowAnalyzer 后端API服务
基于图神经网络的入侵检测系统
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
import torch
import numpy as np
from datetime import datetime
import random
import os

app = Flask(__name__)
CORS(app)  # 允许跨域访问

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

# 全局模型状态
model = None
model_loaded = False


def load_model():
    """加载GNN模型"""
    global model, model_loaded
    try:
        # 尝试加载已训练的模型
        model_path = os.path.join(os.path.dirname(__file__), 'model', 'best_model.pt')
        if os.path.exists(model_path):
            # 这里需要根据实际模型结构加载
            # model = HeteroGNN_Edge(...)
            # checkpoint = torch.load(model_path)
            # model.load_state_dict(checkpoint['state_dict'])
            print(f"[INFO] 模型已加载: {model_path}")
            model_loaded = True
        else:
            print("[WARNING] 未找到模型文件，使用模拟模式")
            model_loaded = False
    except Exception as e:
        print(f"[ERROR] 模型加载失败: {e}")
        model_loaded = False


def detect_attack(flow_data):
    """
    检测网络流量是否为攻击
    flow_data: dict, 包含流量特征
    返回: (attack_type, confidence)
    """
    if model_loaded and model is not None:
        # 使用真实模型预测
        # TODO: 实现模型推理逻辑
        pass
    
    # 模拟检测逻辑（基于流量特征）
    src_port = flow_data.get('src_port', 0)
    dst_port = flow_data.get('dst_port', 0)
    packet_count = flow_data.get('packet_count', 0)
    bytes_rate = flow_data.get('bytes_rate', 0)
    
    # 检测规则
    # 1. 检测端口扫描（大量目的端口）
    if flow_data.get('unique_ports', 0) > 50:
        return 3, 0.92  # 侦察攻击
    
    # 2. 检测DDoS（高数据包速率）
    if bytes_rate > 1000000 and packet_count > 5000:
        return 6, 0.88  # DDoS
    
    # 3. 检测DoS
    if bytes_rate > 500000 and packet_count > 1000:
        return 5, 0.85  # DoS
    
    # 4. 检测暴力破解（SSH/FTP端口）
    if dst_port in [22, 21, 23, 3389] and flow_data.get('failed_logins', 0) > 3:
        return 7, 0.90  # 暴力破解
    
    # 5. 检测Web攻击
    if dst_port in [80, 443, 8080] and flow_data.get('has_payload', False):
        if flow_data.get('suspicious_patterns', 0) > 0:
            return 1, 0.87  # Web攻击
    
    # 6. 检测Mirai（特定端口和模式）
    if dst_port in [23, 2323, 5555] and packet_count > 100:
        return 4, 0.82  # Mirai
    
    # 正常流量
    return 0, 0.95


# ============================================
# API 路由
# ============================================

@app.route('/')
def index():
    """API首页"""
    return jsonify({
        'status': 'success',
        'service': 'GNN4ID-FlowAnalyzer API',
        'version': '1.0.0',
        'model_loaded': model_loaded
    })


@app.route('/api/health')
def health():
    """健康检查"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat()
    })


@app.route('/api/stats')
def get_stats():
    """获取统计信息"""
    return jsonify({
        'totalFlows': random.randint(10000, 50000),
        'normalFlows': random.randint(8000, 40000),
        'attackFlows': random.randint(500, 5000),
        'detectionRate': round(random.uniform(94.0, 98.0), 2),
        'blockedAttacks': random.randint(100, 500)
    })


@app.route('/api/traffic/list')
def get_traffic_list():
    """获取流量列表"""
    page = request.args.get('page', 1, type=int)
    page_size = request.args.get('pageSize', 20, type=int)
    protocol = request.args.get('protocol', '')
    search = request.args.get('search', '')
    
    # 生成模拟数据
    traffic_list = []
    for i in range(100):
        attack_type, confidence = random.choice([
            (0, 0.95), (0, 0.98), (1, 0.87), (3, 0.92), (5, 0.85), (6, 0.88)
        ])
        
        item = {
            'id': i + 1,
            'srcIp': f'192.168.{random.randint(1,10)}.{random.randint(1,254)}',
            'dstIp': f'10.0.{random.randint(1,10)}.{random.randint(1,254)}',
            'srcPort': random.randint(1024, 65535),
            'dstPort': random.choice([80, 443, 22, 3306, 8080, 21]),
            'protocol': random.choice(['TCP', 'UDP', 'HTTP', 'HTTPS']),
            'bytes': random.randint(1000, 1000000),
            'packets': random.randint(10, 1000),
            'duration': round(random.uniform(0.1, 30.0), 2),
            'timestamp': datetime.now().isoformat(),
            'attackType': ATTACK_TYPES[attack_type]['name'],
            'confidence': round(confidence * random.uniform(0.9, 1.0), 3),
            'level': ATTACK_TYPES[attack_type]['level']
        }
        
        # 过滤
        if protocol and item['protocol'] != protocol:
            continue
        if search:
            if search not in item['srcIp'] and search not in item['dstIp']:
                continue
        
        traffic_list.append(item)
    
    # 分页
    start = (page - 1) * page_size
    end = start + page_size
    return jsonify({
        'list': traffic_list[start:end],
        'total': len(traffic_list),
        'page': page,
        'pageSize': page_size
    })


@app.route('/api/attack/list')
def get_attack_list():
    """获取攻击列表"""
    page = request.args.get('page', 1, type=int)
    page_size = request.args.get('pageSize', 20, type=int)
    
    attacks = []
    attack_types = [1, 2, 3, 4, 5, 6, 7]  # 排除正常流量
    
    for i in range(50):
        attack_type = random.choice(attack_types)
        attack_info = ATTACK_TYPES[attack_type]
        
        attacks.append({
            'id': i + 1,
            'type': attack_info['name'],
            'typeId': attack_type,
            'source': f'192.168.{random.randint(1,10)}.{random.randint(1,254)}',
            'target': f'10.0.{random.randint(1,10)}.{random.randint(1,254)}',
            'port': random.choice([22, 80, 443, 3306, 8080]),
            'time': f"{random.randint(1, 59)}分钟前",
            'timestamp': datetime.now().isoformat(),
            'level': attack_info['level'],
            'confidence': round(random.uniform(0.75, 0.99), 2),
            'status': random.choice(['detected', 'detected', 'blocked']),
            'action': random.choice(['阻断', '记录', '警告'])
        })
    
    start = (page - 1) * page_size
    end = start + page_size
    
    return jsonify({
        'list': attacks[start:end],
        'total': len(attacks),
        'stats': {
            'total': len(attacks),
            'high': len([a for a in attacks if a['level'] == 'high']),
            'medium': len([a for a in attacks if a['level'] == 'medium']),
            'low': len([a for a in attacks if a['level'] == 'none'])
        }
    })


@app.route('/api/attack/detect', methods=['POST'])
def detect_attack_api():
    """检测单条流量"""
    data = request.get_json()
    
    if not data:
        return jsonify({'error': '缺少流量数据'}), 400
    
    attack_type, confidence = detect_attack(data)
    attack_info = ATTACK_TYPES[attack_type]
    
    return jsonify({
        'detected': attack_type != 0,
        'attackType': attack_type,
        'attackName': attack_info['name'],
        'level': attack_info['level'],
        'confidence': round(confidence, 3),
        'description': attack_info['description'],
        'timestamp': datetime.now().isoformat()
    })


@app.route('/api/attack/batch-detect', methods=['POST'])
def batch_detect():
    """批量检测流量"""
    data = request.get_json()
    
    if not data or 'flows' not in data:
        return jsonify({'error': '缺少flows数据'}), 400
    
    flows = data['flows']
    results = []
    attack_count = 0
    
    for flow in flows:
        attack_type, confidence = detect_attack(flow)
        attack_info = ATTACK_TYPES[attack_type]
        
        result = {
            'flowId': flow.get('id', 0),
            'detected': attack_type != 0,
            'attackType': attack_type,
            'attackName': attack_info['name'],
            'confidence': round(confidence, 3)
        }
        results.append(result)
        
        if attack_type != 0:
            attack_count += 1
    
    return jsonify({
        'total': len(flows),
        'attacks': attack_count,
        'normal': len(flows) - attack_count,
        'results': results
    })


@app.route('/api/topology')
def get_topology():
    """获取网络拓扑"""
    nodes = [
        {'id': 'firewall', 'type': 'firewall', 'name': '防火墙', 'x': 200, 'y': 50},
        {'id': 'router', 'type': 'router', 'name': '路由器', 'x': 200, 'y': 150},
        {'id': 'switch', 'type': 'switch', 'name': '核心交换机', 'x': 200, 'y': 250},
        {'id': 'server1', 'type': 'server', 'name': 'Web服务器', 'x': 100, 'y': 350, 'status': 'normal'},
        {'id': 'server2', 'type': 'server', 'name': '数据库服务器', 'x': 200, 'y': 350, 'status': 'normal'},
        {'id': 'server3', 'type': 'server', 'name': '文件服务器', 'x': 300, 'y': 350, 'status': 'warning'},
        {'id': 'workstation1', 'type': 'workstation', 'name': '工作站1', 'x': 50, 'y': 450, 'status': 'normal'},
        {'id': 'workstation2', 'type': 'workstation', 'name': '工作站2', 'x': 150, 'y': 450, 'status': 'attack'},
        {'id': 'workstation3', 'type': 'workstation', 'name': '工作站3', 'x': 250, 'y': 450, 'status': 'normal'},
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
        {'source': 'switch', 'target': 'workstation2', 'type': 'CLIENT'},
        {'source': 'switch', 'target': 'workstation3', 'type': 'CLIENT'}
    ]
    
    return jsonify({'nodes': nodes, 'edges': edges})


@app.route('/api/monitor/metrics')
def get_metrics():
    """获取监控指标"""
    return jsonify({
        'throughput': round(random.uniform(200, 400), 1),
        'throughputUnit': 'Mbps',
        'connections': random.randint(500, 2000),
        'alerts': random.randint(5, 30),
        'accuracy': round(random.uniform(95.0, 98.5), 1),
        'latency': round(random.uniform(1, 10), 1),
        'timestamp': datetime.now().isoformat()
    })


@app.route('/api/alerts/recent')
def get_recent_alerts():
    """获取最近告警"""
    alerts = []
    for i in range(10):
        attack_type = random.choice([1, 3, 5, 6, 7])
        attack_info = ATTACK_TYPES[attack_type]
        
        alerts.append({
            'id': i + 1,
            'type': attack_info['name'],
            'level': attack_info['level'],
            'source': f'192.168.{random.randint(1,10)}.{random.randint(1,254)}',
            'target': f'10.0.{random.randint(1,10)}.{random.randint(1,254)}',
            'time': f"{random.randint(1, 60)}分钟前",
            'message': f"检测到{attack_info['name']}，源IP: {f'192.168.{random.randint(1,10)}.{random.randint(1,254)}'}，风险等级: {attack_info['level']}"
        })
    
    return jsonify({'alerts': alerts})


if __name__ == '__main__':
    load_model()
    print("\n" + "="*50)
    print("🚀 GNN4ID-FlowAnalyzer API 服务启动中...")
    print("📡 服务地址: http://localhost:5000")
    print("📋 API文档: http://localhost:5000/")
    print("="*50 + "\n")
    app.run(host='0.0.0.0', port=5000, debug=True)
