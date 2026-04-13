"""
GNN4ID-FlowAnalyzer 后端API服务（简化版）
网络入侵检测系统 - 演示版
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
from datetime import datetime
import random
import os
import csv
import io

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
    'recent_alerts': [],
    'uploaded_flows': []  # 存储上传的流量数据
}

# 存储的流量数据（用于展示）
stored_flows = []


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
    # 如果有上传数据，使用实际数据统计
    if stored_flows:
        total = len(stored_flows)
        attacks = sum(1 for f in stored_flows if f.get('label', 0) > 0)
        normal = total - attacks
        return jsonify({
            'total': total,
            'attacks': attacks,
            'normal': normal,
            'totalFlows': total,
            'attackFlows': attacks,
            'normalFlows': normal,
            'detectionRate': round(97.5, 1),  # 模拟准确率
            'attackRate': round(attacks / max(total, 1) * 100, 1),
            'timestamp': datetime.now().isoformat()
        })
    
    # 模拟数据统计
    return jsonify({
        'total': stats['total'],
        'attacks': stats['attacks'],
        'normal': stats['normal'],
        'totalFlows': stats['total'],
        'attackFlows': stats['attacks'],
        'normalFlows': stats['normal'],
        'detectionRate': round(97.5, 1),
        'attackRate': round(stats['attacks'] / max(stats['total'], 1) * 100, 1),
        'timestamp': datetime.now().isoformat()
    })


@app.route('/api/traffic/list')
def get_traffic_list():
    """获取流量列表"""
    page = int(request.args.get('page', 1))
    pageSize = int(request.args.get('pageSize', 20))
    
    # 如果有上传的数据，返回真实数据
    if stored_flows:
        total = len(stored_flows)
        start = (page - 1) * pageSize
        end = start + pageSize
        page_flows = stored_flows[start:end]
        
        return jsonify({
            'list': page_flows,
            'total': total,
            'page': page,
            'pageSize': pageSize,
            'source': 'uploaded'
        })
    
    # 否则返回模拟数据
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
        'pageSize': pageSize,
        'source': 'simulated'
    })


@app.route('/api/data/upload', methods=['POST'])
def upload_data():
    """上传CSV数据文件"""
    try:
        if 'file' not in request.files:
            # 尝试接收JSON数据
            data = request.get_json()
            if not data or 'flows' not in data:
                return jsonify({'success': False, 'error': '没有文件或数据'}), 400
            
            flows = process_flow_data(data['flows'])
        else:
            file = request.files['file']
            if file.filename == '':
                return jsonify({'success': False, 'error': '文件名为空'}), 400
            
            # 读取文件内容
            content = file.read().decode('utf-8')
            
            # 解析CSV
            flows = parse_csv(content)
        
        if not flows:
            return jsonify({'success': False, 'error': '没有有效数据'}), 400
        
        # 更新存储的数据
        global stored_flows
        stored_flows = flows
        
        # 更新统计数据
        stats['total'] = len(flows)
        stats['attacks'] = sum(1 for f in flows if f.get('label', 0) > 0)
        stats['normal'] = stats['total'] - stats['attacks']
        
        return jsonify({
            'success': True,
            'message': f'成功导入 {len(flows)} 条流量记录',
            'stats': {
                'total': stats['total'],
                'attacks': stats['attacks'],
                'normal': stats['normal'],
                'attackRate': round(stats['attacks'] / max(stats['total'], 1) * 100, 1)
            }
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


def parse_csv(content):
    """解析CSV内容"""
    flows = []
    lines = content.strip().split('\n')
    
    if len(lines) < 2:
        return flows
    
    # 解析表头
    header = lines[0].lower()
    
    # 尝试不同的CSV格式
    try:
        reader = csv.DictReader(io.StringIO(content))
        headers = reader.fieldnames
        
        for i, row in enumerate(reader):
            flow = parse_flow_row(row, headers)
            if flow:
                flows.append(flow)
    except:
        # 简单解析
        for i, line in enumerate(lines[1:100]):  # 最多100条
            try:
                parts = line.split(',')
                if len(parts) >= 5:
                    flow = {
                        'id': i + 1,
                        'src_ip': parts[0].strip() if len(parts) > 0 else '0.0.0.0',
                        'dst_ip': parts[1].strip() if len(parts) > 1 else '0.0.0.0',
                        'protocol': parts[2].strip().upper() if len(parts) > 2 else 'TCP',
                        'src_port': int(parts[3].strip()) if len(parts) > 3 and parts[3].strip().isdigit() else 0,
                        'dst_port': int(parts[4].strip()) if len(parts) > 4 and parts[4].strip().isdigit() else 0,
                        'bytes': int(parts[5].strip()) if len(parts) > 5 and parts[5].strip().isdigit() else 0,
                        'label': int(parts[-1].strip()) if parts[-1].strip().isdigit() else 0,
                        'timestamp': datetime.now().isoformat()
                    }
                    # 添加攻击类型
                    attack_type = flow['label']
                    if attack_type in ATTACK_TYPES:
                        flow['attack_type'] = ATTACK_TYPES[attack_type]['name']
                        flow['level'] = ATTACK_TYPES[attack_type]['level']
                    else:
                        flow['attack_type'] = '正常流量'
                        flow['level'] = 'none'
                    
                    flows.append(flow)
            except:
                continue
    
    return flows


def parse_flow_row(row, headers):
    """解析流量数据行"""
    # 常见列名映射
    src_ip_keys = ['srcip', 'source_ip', 'src_ip', 'source', 'ip_src', 'src']
    dst_ip_keys = ['dstip', 'dest_ip', 'dst_ip', 'destination', 'ip_dst', 'dst']
    proto_keys = ['protocol', 'proto']
    sport_keys = ['sport', 'src_port', 'source_port', 'srcport']
    dport_keys = ['dport', 'dst_port', 'dest_port', 'dstport']
    bytes_keys = ['bytes', 'byte', 'length', 'size', 'totbytes']
    label_keys = ['label', 'class', 'attack', 'type', 'result', 'label_1']
    
    def find_value(keys):
        for key in keys:
            for header in headers:
                if key in header.lower():
                    return row.get(header, '')
        return ''
    
    src_ip = find_value(src_ip_keys)
    dst_ip = find_value(dst_ip_keys)
    
    if not src_ip and not dst_ip:
        return None
    
    protocol = find_value(proto_keys).upper()
    if not protocol:
        protocol = 'TCP'
    
    try:
        src_port = int(find_value(sport_keys))
    except:
        src_port = 0
    
    try:
        dst_port = int(find_value(dport_keys))
    except:
        dst_port = 0
    
    try:
        bytes_val = int(find_value(bytes_keys))
    except:
        bytes_val = 0
    
    try:
        label = int(find_value(label_keys))
    except:
        label = 0
    
    flow = {
        'id': len(stored_flows) + len([]),
        'src_ip': str(src_ip),
        'dst_ip': str(dst_ip),
        'protocol': protocol,
        'src_port': src_port,
        'dst_port': dst_port,
        'bytes': bytes_val,
        'packets': 1,
        'label': label,
        'timestamp': datetime.now().isoformat()
    }
    
    # 添加攻击类型
    if label in ATTACK_TYPES:
        flow['attack_type'] = ATTACK_TYPES[label]['name']
        flow['level'] = ATTACK_TYPES[label]['level']
    else:
        flow['attack_type'] = '正常流量'
        flow['level'] = 'none'
    
    return flow


def process_flow_data(flows_data):
    """处理流量数据列表"""
    flows = []
    for i, row in enumerate(flows_data):
        flow = parse_flow_row(row, row.keys())
        if flow:
            flow['id'] = i + 1
            flows.append(flow)
    return flows


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
