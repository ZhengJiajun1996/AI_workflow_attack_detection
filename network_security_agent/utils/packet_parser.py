"""
网络安全检测智能体 - 报文解析工具
"""
import re
import json
import base64
import urllib.parse
from typing import Dict, List, Optional, Any
from datetime import datetime
from .data_structures import HttpPacket


class PacketParser:
    """HTTP报文解析器"""
    
    def __init__(self):
        self.suspicious_patterns = {
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
    
    def parse_raw_packet(self, raw_data: str) -> HttpPacket:
        """解析原始报文数据"""
        try:
            # 假设输入是JSON格式的报文数据
            if raw_data.strip().startswith('{'):
                packet_data = json.loads(raw_data)
                return self._parse_json_packet(packet_data)
            else:
                # 处理原始HTTP报文格式
                return self._parse_raw_http(raw_data)
        except Exception as e:
            raise ValueError(f"报文解析失败: {str(e)}")
    
    def _parse_json_packet(self, data: Dict[str, Any]) -> HttpPacket:
        """解析JSON格式的报文数据"""
        headers = data.get('headers', {})
        
        return HttpPacket(
            timestamp=datetime.fromisoformat(data.get('timestamp', datetime.now().isoformat())),
            source_ip=data.get('source_ip', ''),
            destination_ip=data.get('destination_ip', ''),
            source_port=data.get('source_port', 0),
            destination_port=data.get('destination_port', 80),
            method=data.get('method', 'GET'),
            url=data.get('url', ''),
            headers=headers,
            body=data.get('body', ''),
            user_agent=headers.get('User-Agent', ''),
            referer=headers.get('Referer'),
            cookies=self._parse_cookies(headers.get('Cookie', '')),
            query_params=self._parse_query_params(data.get('url', '')),
            post_params=self._parse_post_params(data.get('body', ''), 
                                              headers.get('Content-Type', ''))
        )
    
    def _parse_raw_http(self, raw_data: str) -> HttpPacket:
        """解析原始HTTP报文格式"""
        lines = raw_data.split('\n')
        if not lines:
            raise ValueError("空报文数据")
        
        # 解析请求行
        request_line = lines[0].strip()
        parts = request_line.split(' ')
        if len(parts) < 2:
            raise ValueError("无效的HTTP请求行")
        
        method = parts[0]
        url = parts[1]
        
        # 解析头部
        headers = {}
        body_start = 0
        for i, line in enumerate(lines[1:], 1):
            if line.strip() == '':
                body_start = i + 1
                break
            if ':' in line:
                key, value = line.split(':', 1)
                headers[key.strip()] = value.strip()
        
        # 解析消息体
        body = '\n'.join(lines[body_start:]) if body_start < len(lines) else ''
        
        return HttpPacket(
            timestamp=datetime.now(),
            source_ip='',  # 需要从网络层获取
            destination_ip='',
            source_port=0,
            destination_port=80,
            method=method,
            url=url,
            headers=headers,
            body=body,
            user_agent=headers.get('User-Agent', ''),
            referer=headers.get('Referer'),
            cookies=self._parse_cookies(headers.get('Cookie', '')),
            query_params=self._parse_query_params(url),
            post_params=self._parse_post_params(body, headers.get('Content-Type', ''))
        )
    
    def _parse_cookies(self, cookie_string: str) -> Dict[str, str]:
        """解析Cookie字符串"""
        cookies = {}
        if cookie_string:
            for item in cookie_string.split(';'):
                if '=' in item:
                    key, value = item.split('=', 1)
                    cookies[key.strip()] = value.strip()
        return cookies
    
    def _parse_query_params(self, url: str) -> Dict[str, str]:
        """解析URL查询参数"""
        if '?' not in url:
            return {}
        
        query_string = url.split('?', 1)[1]
        return dict(urllib.parse.parse_qsl(query_string))
    
    def _parse_post_params(self, body: str, content_type: str) -> Dict[str, str]:
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
    
    def extract_suspicious_patterns(self, packet: HttpPacket) -> Dict[str, List[str]]:
        """提取可疑模式"""
        found_patterns = {}
        
        # 检查URL
        url_patterns = self._check_patterns(packet.url)
        if url_patterns:
            found_patterns['url'] = url_patterns
        
        # 检查查询参数
        query_text = ' '.join(packet.query_params.values())
        query_patterns = self._check_patterns(query_text)
        if query_patterns:
            found_patterns['query_params'] = query_patterns
        
        # 检查POST参数
        post_text = ' '.join(packet.post_params.values())
        post_patterns = self._check_patterns(post_text)
        if post_patterns:
            found_patterns['post_params'] = post_patterns
        
        # 检查请求体
        body_patterns = self._check_patterns(packet.body)
        if body_patterns:
            found_patterns['body'] = body_patterns
        
        # 检查头部
        headers_text = ' '.join(packet.headers.values())
        header_patterns = self._check_patterns(headers_text)
        if header_patterns:
            found_patterns['headers'] = header_patterns
        
        return found_patterns
    
    def _check_patterns(self, text: str) -> List[str]:
        """检查文本中的可疑模式"""
        found = []
        text_lower = text.lower()
        
        for category, patterns in self.suspicious_patterns.items():
            for pattern in patterns:
                if re.search(pattern, text_lower, re.IGNORECASE):
                    found.append(f"{category}:{pattern}")
        
        return found