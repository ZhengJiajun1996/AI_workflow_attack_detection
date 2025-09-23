"""
网络安全检测智能体 - 独立报文输入模块
适用于工作流编排中的Python代码执行模块，无需外部依赖
"""
import json
import re
import urllib.parse
from datetime import datetime
from typing import Dict, Any, List, Optional


def execute_packet_input(raw_packet_data: str) -> str:
    """
    工作流编排调用的主函数 - 独立版本
    
    Args:
        raw_packet_data: 原始报文数据（JSON字符串格式）
        
    Returns:
        str: JSON格式的处理结果
    """
    
    # 内嵌的数据结构和工具函数
    def parse_cookies(cookie_string: str) -> Dict[str, str]:
        """解析Cookie字符串"""
        cookies = {}
        if cookie_string:
            for item in cookie_string.split(';'):
                if '=' in item:
                    key, value = item.split('=', 1)
                    cookies[key.strip()] = value.strip()
        return cookies
    
    def parse_query_params(url: str) -> Dict[str, str]:
        """解析URL查询参数"""
        if '?' not in url:
            return {}
        
        query_string = url.split('?', 1)[1]
        return dict(urllib.parse.parse_qsl(query_string))
    
    def parse_post_params(body: str, content_type: str) -> Dict[str, str]:
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
    
    def extract_suspicious_patterns(packet_data: Dict) -> Dict[str, List[str]]:
        """提取可疑模式"""
        suspicious_patterns = {
            'sql_injection': [
                r'union\s+select', r'or\s+1\s*=\s*1', r'and\s+1\s*=\s*1',
                r'drop\s+table', r'insert\s+into', r'delete\s+from',
                r'update\s+set', r'exec\s*\(', r'sp_executesql'
            ],
            'xss': [
                r'<script[^>]*>', r'javascript:', r'onerror\s*=',
                r'onload\s*=', r'onclick\s*=', r'alert\s*\(',
                r'document\.cookie', r'eval\s*\('
            ],
            'command_injection': [
                r';\s*cat\s+', r';\s*ls\s+', r';\s*pwd',
                r';\s*id\s*;', r'\|\s*nc\s+', r'&&\s*curl'
            ]
        }
        
        found_patterns = {}
        test_strings = [
            packet_data.get('url', ''),
            packet_data.get('body', ''),
            ' '.join(packet_data.get('query_params', {}).values()),
            ' '.join(packet_data.get('post_params', {}).values()),
            ' '.join(packet_data.get('headers', {}).values())
        ]
        
        for category, patterns in suspicious_patterns.items():
            for pattern in patterns:
                for test_string in test_strings:
                    if re.search(pattern, test_string.lower(), re.IGNORECASE):
                        if category not in found_patterns:
                            found_patterns[category] = []
                        found_patterns[category].append(f"{category}:{pattern}")
        
        return found_patterns
    
    def validate_packet(packet_data: Dict) -> Dict[str, Any]:
        """验证报文基础信息"""
        validation = {
            'is_valid': True,
            'warnings': [],
            'anomalies': []
        }
        
        # 检查必要字段
        if not packet_data.get('method'):
            validation['warnings'].append('缺少HTTP方法')
            validation['is_valid'] = False
            
        if not packet_data.get('url'):
            validation['warnings'].append('缺少URL路径')
            validation['is_valid'] = False
        
        # 检查异常特征
        url = packet_data.get('url', '')
        body = packet_data.get('body', '')
        method = packet_data.get('method', '')
        user_agent = packet_data.get('user_agent', '')
        
        if len(url) > 2048:
            validation['anomalies'].append('URL长度异常')
            
        if len(body) > 10 * 1024 * 1024:  # 10MB
            validation['anomalies'].append('请求体过大')
            
        if method in ['GET', 'HEAD'] and body:
            validation['anomalies'].append('GET/HEAD请求包含请求体')
        
        # 检查可疑User-Agent
        suspicious_ua_patterns = [
            'sqlmap', 'nmap', 'nikto', 'dirb', 'gobuster',
            'burpsuite', 'owasp zap', 'w3af', 'acunetix'
        ]
        
        ua_lower = user_agent.lower()
        for pattern in suspicious_ua_patterns:
            if pattern in ua_lower:
                validation['anomalies'].append(f'可疑User-Agent: {pattern}')
        
        return validation
    
    # 主处理逻辑
    try:
        packet_count = 1  # 简化处理
        
        # 解析报文
        if raw_packet_data.strip().startswith('{'):
            packet_input = json.loads(raw_packet_data)
        else:
            raise ValueError("仅支持JSON格式的报文数据")
        
        headers = packet_input.get('headers', {})
        
        # 构建标准化的报文数据
        packet_data = {
            'timestamp': packet_input.get('timestamp', datetime.now().isoformat()),
            'source_ip': packet_input.get('source_ip', ''),
            'destination_ip': packet_input.get('destination_ip', ''),
            'source_port': packet_input.get('source_port', 0),
            'destination_port': packet_input.get('destination_port', 80),
            'method': packet_input.get('method', 'GET'),
            'url': packet_input.get('url', ''),
            'headers': headers,
            'body': packet_input.get('body', ''),
            'user_agent': headers.get('User-Agent', ''),
            'referer': headers.get('Referer'),
        }
        
        # 解析参数
        packet_data['cookies'] = parse_cookies(headers.get('Cookie', ''))
        packet_data['query_params'] = parse_query_params(packet_data['url'])
        packet_data['post_params'] = parse_post_params(
            packet_data['body'], 
            headers.get('Content-Type', '')
        )
        
        # 基础验证
        validation_result = validate_packet(packet_data)
        
        # 提取可疑模式
        suspicious_patterns = extract_suspicious_patterns(packet_data)
        
        # 构建输出结果
        result = {
            'packet_id': f"PKT_{packet_count}_{int(datetime.fromisoformat(packet_data['timestamp']).timestamp())}",
            'timestamp': packet_data['timestamp'],
            'source_ip': packet_data['source_ip'],
            'destination_ip': packet_data['destination_ip'],
            'method': packet_data['method'],
            'url': packet_data['url'],
            'headers': packet_data['headers'],
            'body': packet_data['body'],
            'user_agent': packet_data['user_agent'],
            'referer': packet_data['referer'],
            'cookies': packet_data['cookies'],
            'query_params': packet_data['query_params'],
            'post_params': packet_data['post_params'],
            'validation': validation_result,
            'suspicious_patterns': suspicious_patterns,
            'packet_size': len(raw_packet_data),
            'processing_time': datetime.now().isoformat()
        }
        
        return json.dumps(result, ensure_ascii=False, indent=2)
        
    except Exception as e:
        error_result = {
            'error': True,
            'error_message': str(e),
            'packet_id': f"ERR_{packet_count}_{int(datetime.now().timestamp())}",
            'timestamp': datetime.now().isoformat()
        }
        return json.dumps(error_result, ensure_ascii=False, indent=2)


# 测试代码
if __name__ == "__main__":
    sample_packet = {
        "timestamp": "2024-01-15T10:30:00",
        "source_ip": "192.168.1.100",
        "destination_ip": "10.0.0.1",
        "source_port": 54321,
        "destination_port": 80,
        "method": "POST",
        "url": "/login.php?id=1' OR '1'='1",
        "headers": {
            "Host": "example.com",
            "User-Agent": "Mozilla/5.0 (compatible; sqlmap/1.6.12)",
            "Content-Type": "application/x-www-form-urlencoded",
            "Cookie": "session=abc123; auth=token456"
        },
        "body": "username=admin&password=' OR '1'='1-- "
    }
    
    result = execute_packet_input(json.dumps(sample_packet))
    print("独立报文输入模块测试结果:")
    print(result)