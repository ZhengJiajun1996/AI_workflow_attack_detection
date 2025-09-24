"""
网络攻击检测智能体 - 循环体内报文处理模块
适用于循环体模块的代码执行模块，标准main()函数格式
"""
import json
import re
import urllib.parse
from datetime import datetime
from typing import Dict, Any


def main(current_packet, context_data):
    """
    循环体内的报文处理主函数
    
    Args:
        current_packet: 当前处理的报文数据（文本格式）
        context_data: 上下文数据和中间状态（文本格式）
        
    Returns:
        dict: 包含处理结果和更新后的上下文数据
    """
    
    def parse_packet(packet_str):
        """解析单个报文"""
        try:
            packet_data = json.loads(packet_str)
            
            # 标准化报文格式
            headers = packet_data.get('headers', {})
            
            parsed_packet = {
                'timestamp': packet_data.get('timestamp', datetime.now().isoformat()),
                'source_ip': packet_data.get('source_ip', ''),
                'method': packet_data.get('method', 'GET'),
                'url': packet_data.get('url', ''),
                'headers': headers,
                'body': packet_data.get('body', ''),
                'user_agent': headers.get('User-Agent', ''),
                'cookies': parse_cookies(headers.get('Cookie', '')),
                'query_params': parse_query_params(packet_data.get('url', '')),
                'post_params': parse_post_params(packet_data.get('body', ''), 
                                               headers.get('Content-Type', ''))
            }
            
            return parsed_packet
            
        except Exception as e:
            return {'error': f"报文解析失败: {str(e)}"}
    
    def parse_cookies(cookie_string):
        """解析Cookie字符串"""
        cookies = {}
        if cookie_string:
            for item in cookie_string.split(';'):
                if '=' in item:
                    key, value = item.split('=', 1)
                    cookies[key.strip()] = value.strip()
        return cookies
    
    def parse_query_params(url):
        """解析URL查询参数"""
        if '?' not in url:
            return {}
        query_string = url.split('?', 1)[1]
        return dict(urllib.parse.parse_qsl(query_string))
    
    def parse_post_params(body, content_type):
        """解析POST参数"""
        if not body:
            return {}
        
        if 'application/x-www-form-urlencoded' in content_type:
            return dict(urllib.parse.parse_qsl(body))
        elif 'application/json' in content_type:
            try:
                json_data = json.loads(body)
                if isinstance(json_data, dict):
                    return {str(k): str(v) for k, v in json_data.items()}
            except json.JSONDecodeError:
                pass
        
        return {'raw_body': body}
    
    def detect_attack_patterns(packet):
        """检测攻击模式"""
        attack_patterns = {
            'sql_injection': [
                r'union\s+select', r'or\s+1\s*=\s*1', r'and\s+1\s*=\s*1',
                r'drop\s+table', r'insert\s+into', r'delete\s+from',
                r'--\s', r'#.*', r'/\*.*\*/'
            ],
            'xss': [
                r'<script[^>]*>', r'javascript:', r'onerror\s*=',
                r'onload\s*=', r'alert\s*\(', r'document\.cookie'
            ],
            'command_injection': [
                r';\s*cat\s+', r';\s*ls\s+', r';\s*pwd',
                r'\|\s*nc\s+', r'&&\s*curl', r'`.*`'
            ],
            'directory_traversal': [
                r'\.\./|\.\.\\\|%2e%2e%2f',
                r'/etc/passwd|/etc/shadow|win\.ini'
            ]
        }
        
        detected_attacks = []
        test_strings = [
            packet.get('url', ''),
            packet.get('body', ''),
            packet.get('user_agent', ''),
            ' '.join(packet.get('query_params', {}).values()),
            ' '.join(packet.get('post_params', {}).values())
        ]
        
        for attack_type, patterns in attack_patterns.items():
            for pattern in patterns:
                for test_string in test_strings:
                    if re.search(pattern, test_string, re.IGNORECASE):
                        detected_attacks.append({
                            'type': attack_type,
                            'pattern': pattern,
                            'matched_content': test_string[:100],
                            'confidence': 0.8
                        })
                        break
        
        return detected_attacks
    
    def update_context_stats(packet, context):
        """更新上下文统计信息"""
        source_ip = packet.get('source_ip', '')
        url = packet.get('url', '')
        current_time = datetime.now().timestamp()
        
        # 更新IP统计
        if source_ip not in context['ip_stats']:
            context['ip_stats'][source_ip] = {
                'request_times': [],
                'urls': [],  # 改为list以支持JSON序列化
                'attack_count': 0,
                'first_seen': current_time
            }
        
        ip_stats = context['ip_stats'][source_ip]
        ip_stats['request_times'].append(current_time)
        # 使用list存储，避免重复
        if url not in ip_stats['urls']:
            ip_stats['urls'].append(url)
        
        # 保持最近1小时的请求记录
        cutoff_time = current_time - 3600
        ip_stats['request_times'] = [t for t in ip_stats['request_times'] if t > cutoff_time]
        
        # 计算请求频率
        recent_requests = [t for t in ip_stats['request_times'] if current_time - t <= 300]  # 5分钟
        request_frequency = len(recent_requests) / 5.0
        
        return {
            'request_frequency_5min': request_frequency,
            'total_requests': len(ip_stats['request_times']),
            'unique_urls': len(ip_stats['urls']),
            'session_duration': current_time - ip_stats['first_seen']
        }
    
    def calculate_risk_score(packet, context_stats, detected_attacks):
        """计算风险评分"""
        risk_score = 0
        risk_factors = []
        
        # 基于检测到的攻击
        if detected_attacks:
            risk_score += 50
            risk_factors.append('attack_patterns_detected')
            
        # 基于请求频率
        freq = context_stats.get('request_frequency_5min', 0)
        if freq > 20:
            risk_score += 30
            risk_factors.append('high_frequency_requests')
        elif freq > 10:
            risk_score += 15
            risk_factors.append('moderate_frequency_requests')
        
        # 基于User-Agent
        user_agent = packet.get('user_agent', '').lower()
        suspicious_ua = ['sqlmap', 'nmap', 'nikto', 'curl', 'python', 'scanner']
        if any(ua in user_agent for ua in suspicious_ua):
            risk_score += 25
            risk_factors.append('suspicious_user_agent')
        
        # 基于URL长度和复杂度
        url = packet.get('url', '')
        if len(url) > 200:
            risk_score += 10
            risk_factors.append('long_url')
        
        # 确定风险等级
        if risk_score >= 80:
            risk_level = 'critical'
        elif risk_score >= 60:
            risk_level = 'high'
        elif risk_score >= 40:
            risk_level = 'medium'
        else:
            risk_level = 'low'
        
        return {
            'risk_score': min(risk_score, 100),
            'risk_level': risk_level,
            'risk_factors': risk_factors,
            'requires_llm_analysis': risk_score >= 50
        }
    
    # 主处理逻辑
    try:
        # 解析输入数据
        packet = parse_packet(current_packet)
        if 'error' in packet:
            return {
                'output': json.dumps({
                    'error': True,
                    'message': packet['error'],
                    'timestamp': datetime.now().isoformat()
                })
            }
        
        # 解析上下文数据
        try:
            context = json.loads(context_data) if context_data.strip() else {
                'ip_stats': {},
                'global_stats': {
                    'total_packets': 0,
                    'attack_packets': 0,
                    'start_time': datetime.now().timestamp()
                },
                'recent_attacks': []
            }
        except:
            context = {
                'ip_stats': {},
                'global_stats': {
                    'total_packets': 0,
                    'attack_packets': 0,
                    'start_time': datetime.now().timestamp()
                },
                'recent_attacks': []
            }
        
        # 检测攻击模式
        detected_attacks = detect_attack_patterns(packet)
        
        # 更新上下文统计
        context_stats = update_context_stats(packet, context)
        
        # 计算风险评分
        risk_assessment = calculate_risk_score(packet, context_stats, detected_attacks)
        
        # 更新全局统计
        context['global_stats']['total_packets'] += 1
        if detected_attacks:
            context['global_stats']['attack_packets'] += 1
            context['recent_attacks'].append({
                'timestamp': datetime.now().isoformat(),
                'source_ip': packet.get('source_ip'),
                'attack_types': [attack['type'] for attack in detected_attacks],
                'risk_level': risk_assessment['risk_level']
            })
            # 保持最近100个攻击记录
            context['recent_attacks'] = context['recent_attacks'][-100:]
        
        # 构建处理结果
        result = {
            'packet_id': f"PKT_{context['global_stats']['total_packets']}_{int(datetime.now().timestamp())}",
            'timestamp': datetime.now().isoformat(),
            'source_ip': packet.get('source_ip'),
            'method': packet.get('method'),
            'url': packet.get('url'),
            'is_attack': len(detected_attacks) > 0,
            'detected_attacks': detected_attacks,
            'risk_assessment': risk_assessment,
            'context_stats': context_stats,
            'requires_llm_analysis': risk_assessment['requires_llm_analysis']
        }
        
        return {
            'output': json.dumps({
                'processed_packet': result,
                'updated_context': context
            })
        }
        
    except Exception as e:
        return {
            'output': json.dumps({
                'error': True,
                'message': f"处理失败: {str(e)}",
                'timestamp': datetime.now().isoformat()
            })
        }


# 测试代码
if __name__ == "__main__":
    # 测试用例
    test_packet = json.dumps({
        "timestamp": "2024-01-15T10:30:00Z",
        "source_ip": "192.168.1.100",
        "method": "POST",
        "url": "/login.php?id=1' UNION SELECT user,password FROM users--",
        "headers": {
            "Host": "example.com",
            "User-Agent": "sqlmap/1.6.12",
            "Content-Type": "application/x-www-form-urlencoded"
        },
        "body": "username=admin&password=' OR '1'='1-- "
    })
    
    test_context = ""  # 空的初始上下文
    
    result = main(test_packet, test_context)
    print("报文处理模块测试结果:")
    print(json.dumps(json.loads(result['output']), ensure_ascii=False, indent=2))