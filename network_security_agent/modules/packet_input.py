"""
网络安全检测智能体 - 报文输入模块
工作流编排中的Python代码模块
"""
import json
import logging
from datetime import datetime
from typing import Dict, Any, Optional
from ..utils.data_structures import HttpPacket
from ..utils.packet_parser import PacketParser


class PacketInputModule:
    """报文输入模块 - 处理旁路镜像转发的HTTP请求报文"""
    
    def __init__(self):
        self.parser = PacketParser()
        self.logger = logging.getLogger(__name__)
        self.packet_count = 0
        
    def process_input_packet(self, raw_packet_data: str) -> Dict[str, Any]:
        """
        处理输入的报文数据
        
        Args:
            raw_packet_data: 原始报文数据（JSON字符串格式）
            
        Returns:
            Dict: 包含解析后的报文信息和基础统计
        """
        try:
            self.packet_count += 1
            
            # 解析报文
            packet = self.parser.parse_raw_packet(raw_packet_data)
            
            # 基础验证
            validation_result = self._validate_packet(packet)
            
            # 提取初步可疑模式
            suspicious_patterns = self.parser.extract_suspicious_patterns(packet)
            
            # 构建输出结果
            result = {
                'packet_id': f"PKT_{self.packet_count}_{int(packet.timestamp.timestamp())}",
                'timestamp': packet.timestamp.isoformat(),
                'source_ip': packet.source_ip,
                'destination_ip': packet.destination_ip,
                'method': packet.method,
                'url': packet.url,
                'headers': packet.headers,
                'body': packet.body,
                'user_agent': packet.user_agent,
                'referer': packet.referer,
                'cookies': packet.cookies,
                'query_params': packet.query_params,
                'post_params': packet.post_params,
                'validation': validation_result,
                'suspicious_patterns': suspicious_patterns,
                'packet_size': len(raw_packet_data),
                'processing_time': datetime.now().isoformat()
            }
            
            self.logger.info(f"报文处理完成: {result['packet_id']}")
            return result
            
        except Exception as e:
            self.logger.error(f"报文处理失败: {str(e)}")
            return {
                'error': True,
                'error_message': str(e),
                'packet_id': f"ERR_{self.packet_count}_{int(datetime.now().timestamp())}",
                'timestamp': datetime.now().isoformat()
            }
    
    def _validate_packet(self, packet: HttpPacket) -> Dict[str, Any]:
        """验证报文基础信息"""
        validation = {
            'is_valid': True,
            'warnings': [],
            'anomalies': []
        }
        
        # 检查必要字段
        if not packet.method:
            validation['warnings'].append('缺少HTTP方法')
            validation['is_valid'] = False
            
        if not packet.url:
            validation['warnings'].append('缺少URL路径')
            validation['is_valid'] = False
        
        # 检查异常特征
        if len(packet.url) > 2048:
            validation['anomalies'].append('URL长度异常')
            
        if len(packet.body) > 10 * 1024 * 1024:  # 10MB
            validation['anomalies'].append('请求体过大')
            
        if packet.method in ['GET', 'HEAD'] and packet.body:
            validation['anomalies'].append('GET/HEAD请求包含请求体')
            
        # 检查可疑User-Agent
        suspicious_ua_patterns = [
            'sqlmap', 'nmap', 'nikto', 'dirb', 'gobuster',
            'burpsuite', 'owasp zap', 'w3af', 'acunetix'
        ]
        
        ua_lower = packet.user_agent.lower()
        for pattern in suspicious_ua_patterns:
            if pattern in ua_lower:
                validation['anomalies'].append(f'可疑User-Agent: {pattern}')
        
        return validation


# 工作流编排中使用的函数接口
def execute_packet_input(input_data: str) -> str:
    """
    工作流编排调用的主函数
    
    Args:
        input_data: 输入的原始报文数据
        
    Returns:
        str: JSON格式的处理结果
    """
    module = PacketInputModule()
    result = module.process_input_packet(input_data)
    return json.dumps(result, ensure_ascii=False, indent=2)


# 示例使用代码（用于测试）
if __name__ == "__main__":
    # 测试用例
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
    print("报文输入模块测试结果:")
    print(result)