"""
网络安全检测智能体 - 上下文特征提取模块
工作流编排中的Python代码模块
"""
import json
import time
import hashlib
from datetime import datetime, timedelta
from collections import defaultdict, deque
from typing import Dict, Any, List, Optional
from ..utils.data_structures import ContextFeatures


class ContextFeatureExtractor:
    """上下文特征提取器 - 提取并统计网络攻击检测相关特征"""
    
    def __init__(self, time_window_minutes: int = 60):
        """
        初始化特征提取器
        
        Args:
            time_window_minutes: 时间窗口大小（分钟）
        """
        self.time_window = time_window_minutes * 60  # 转换为秒
        
        # 存储历史数据的数据结构
        self.ip_stats = defaultdict(lambda: {
            'requests': deque(),
            'urls': set(),
            'errors': deque(),
            'sessions': defaultdict(list)
        })
        
        self.url_stats = defaultdict(lambda: {
            'requests': deque(),
            'ips': set(),
            'parameters': set()
        })
        
        # 全局统计
        self.global_stats = {
            'total_requests': 0,
            'start_time': time.time()
        }
        
    def extract_features(self, packet_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        提取上下文特征
        
        Args:
            packet_data: 报文输入模块的输出数据
            
        Returns:
            Dict: 包含上下文特征的字典
        """
        try:
            current_time = time.time()
            source_ip = packet_data.get('source_ip', '')
            url = packet_data.get('url', '')
            method = packet_data.get('method', '')
            
            # 清理过期数据
            self._cleanup_expired_data(current_time)
            
            # 提取IP相关特征
            ip_features = self._extract_ip_features(source_ip, current_time, packet_data)
            
            # 提取URL相关特征
            url_features = self._extract_url_features(url, current_time, packet_data)
            
            # 提取时间相关特征
            time_features = self._extract_time_features(source_ip, current_time)
            
            # 提取异常特征
            anomaly_features = self._extract_anomaly_features(packet_data)
            
            # 提取会话特征
            session_features = self._extract_session_features(source_ip, packet_data, current_time)
            
            # 更新统计数据
            self._update_statistics(source_ip, url, current_time, packet_data)
            
            # 构建完整的上下文特征
            context_features = {
                'extraction_timestamp': datetime.now().isoformat(),
                'packet_id': packet_data.get('packet_id', ''),
                'ip_features': ip_features,
                'url_features': url_features,
                'time_features': time_features,
                'anomaly_features': anomaly_features,
                'session_features': session_features,
                'risk_indicators': self._calculate_risk_indicators(
                    ip_features, url_features, time_features, anomaly_features
                )
            }
            
            return context_features
            
        except Exception as e:
            return {
                'error': True,
                'error_message': str(e),
                'packet_id': packet_data.get('packet_id', ''),
                'extraction_timestamp': datetime.now().isoformat()
            }
    
    def _extract_ip_features(self, ip: str, current_time: float, packet_data: Dict) -> Dict[str, Any]:
        """提取IP相关特征"""
        ip_data = self.ip_stats[ip]
        
        # 计算请求频率
        recent_requests = [t for t in ip_data['requests'] if current_time - t <= 300]  # 5分钟内
        request_frequency = len(recent_requests) / 5.0 if recent_requests else 0.0
        
        # 计算错误率
        recent_errors = [t for t in ip_data['errors'] if current_time - t <= 1800]  # 30分钟内
        error_rate = len(recent_errors) / max(len(recent_requests), 1)
        
        return {
            'total_requests': len(ip_data['requests']),
            'request_frequency_5min': request_frequency,
            'unique_urls_accessed': len(ip_data['urls']),
            'error_rate_30min': error_rate,
            'is_new_ip': len(ip_data['requests']) == 0,
            'first_seen': min(ip_data['requests']) if ip_data['requests'] else current_time
        }
    
    def _extract_url_features(self, url: str, current_time: float, packet_data: Dict) -> Dict[str, Any]:
        """提取URL相关特征"""
        url_data = self.url_stats[url]
        query_params = packet_data.get('query_params', {})
        post_params = packet_data.get('post_params', {})
        
        # 分析参数
        all_params = {**query_params, **post_params}
        param_count = len(all_params)
        
        # 检查参数中的可疑内容
        suspicious_param_patterns = [
            'script', 'javascript', 'vbscript', 'onload', 'onerror',
            'union', 'select', 'insert', 'delete', 'drop', 'exec',
            '../', '..\\', '/etc/', 'cmd.exe', 'powershell'
        ]
        
        suspicious_params = []
        for key, value in all_params.items():
            param_text = f"{key}={value}".lower()
            for pattern in suspicious_param_patterns:
                if pattern in param_text:
                    suspicious_params.append(f"{key}:{pattern}")
        
        return {
            'access_count': len(url_data['requests']),
            'unique_ips_accessed': len(url_data['ips']),
            'parameter_count': param_count,
            'suspicious_parameters': suspicious_params,
            'url_length': len(url),
            'has_query_string': '?' in url,
            'path_depth': url.count('/'),
            'contains_encoded_chars': '%' in url
        }
    
    def _extract_time_features(self, ip: str, current_time: float) -> Dict[str, Any]:
        """提取时间相关特征"""
        ip_requests = self.ip_stats[ip]['requests']
        
        # 计算不同时间窗口的请求数
        requests_1min = len([t for t in ip_requests if current_time - t <= 60])
        requests_5min = len([t for t in ip_requests if current_time - t <= 300])
        requests_1hour = len([t for t in ip_requests if current_time - t <= 3600])
        
        # 计算请求间隔
        intervals = []
        if len(ip_requests) >= 2:
            sorted_requests = sorted(ip_requests)
            intervals = [sorted_requests[i] - sorted_requests[i-1] 
                        for i in range(1, min(len(sorted_requests), 11))]  # 最近10个间隔
        
        avg_interval = sum(intervals) / len(intervals) if intervals else 0
        min_interval = min(intervals) if intervals else 0
        
        return {
            'requests_last_1min': requests_1min,
            'requests_last_5min': requests_5min,
            'requests_last_1hour': requests_1hour,
            'average_request_interval': avg_interval,
            'minimum_request_interval': min_interval,
            'is_burst_pattern': requests_1min > 10,  # 1分钟内超过10个请求
            'is_sustained_pattern': requests_1hour > 100  # 1小时内超过100个请求
        }
    
    def _extract_anomaly_features(self, packet_data: Dict) -> Dict[str, Any]:
        """提取异常特征"""
        headers = packet_data.get('headers', {})
        body = packet_data.get('body', '')
        user_agent = packet_data.get('user_agent', '')
        
        # 检查异常头部
        unusual_headers = []
        common_headers = {
            'host', 'user-agent', 'accept', 'accept-language', 
            'accept-encoding', 'connection', 'referer', 'cookie'
        }
        
        for header in headers.keys():
            if header.lower() not in common_headers:
                unusual_headers.append(header)
        
        # 检查编码异常
        suspicious_encoding = False
        if body:
            try:
                # 检查是否包含多重编码
                if '%25' in body or '\\x' in body or '\\u' in body:
                    suspicious_encoding = True
            except:
                pass
        
        # 检查User-Agent异常
        ua_anomalies = []
        if not user_agent:
            ua_anomalies.append('missing_user_agent')
        elif len(user_agent) < 10:
            ua_anomalies.append('short_user_agent')
        elif any(tool in user_agent.lower() for tool in ['curl', 'wget', 'python', 'java']):
            ua_anomalies.append('tool_user_agent')
        
        return {
            'unusual_headers': unusual_headers,
            'unusual_header_count': len(unusual_headers),
            'large_payload': len(body) > 1024 * 1024,  # 1MB
            'suspicious_encoding': suspicious_encoding,
            'user_agent_anomalies': ua_anomalies,
            'missing_common_headers': self._check_missing_headers(headers),
            'duplicate_parameters': self._check_duplicate_params(packet_data)
        }
    
    def _extract_session_features(self, ip: str, packet_data: Dict, current_time: float) -> Dict[str, Any]:
        """提取会话特征"""
        cookies = packet_data.get('cookies', {})
        session_id = cookies.get('session', cookies.get('sessionid', cookies.get('JSESSIONID', '')))
        
        if session_id:
            session_hash = hashlib.md5(session_id.encode()).hexdigest()
            session_data = self.ip_stats[ip]['sessions'][session_hash]
            session_data.append(current_time)
            
            # 计算会话特征
            session_duration = max(session_data) - min(session_data) if len(session_data) > 1 else 0
            session_request_count = len(session_data)
            
            return {
                'has_session': True,
                'session_duration_seconds': session_duration,
                'session_request_count': session_request_count,
                'session_frequency': session_request_count / max(session_duration / 60, 1)  # 每分钟请求数
            }
        else:
            return {
                'has_session': False,
                'session_duration_seconds': 0,
                'session_request_count': 0,
                'session_frequency': 0
            }
    
    def _calculate_risk_indicators(self, ip_features: Dict, url_features: Dict, 
                                 time_features: Dict, anomaly_features: Dict) -> Dict[str, Any]:
        """计算风险指标"""
        risk_score = 0
        risk_factors = []
        
        # IP风险评估
        if ip_features['request_frequency_5min'] > 20:
            risk_score += 30
            risk_factors.append('high_frequency_requests')
        
        if ip_features['error_rate_30min'] > 0.5:
            risk_score += 25
            risk_factors.append('high_error_rate')
        
        # URL风险评估
        if url_features['suspicious_parameters']:
            risk_score += 40
            risk_factors.append('suspicious_parameters')
        
        if url_features['parameter_count'] > 20:
            risk_score += 15
            risk_factors.append('excessive_parameters')
        
        # 时间模式风险评估
        if time_features['is_burst_pattern']:
            risk_score += 25
            risk_factors.append('burst_pattern')
        
        if time_features['minimum_request_interval'] < 0.1:
            risk_score += 20
            risk_factors.append('automated_requests')
        
        # 异常特征风险评估
        if anomaly_features['user_agent_anomalies']:
            risk_score += 20
            risk_factors.append('suspicious_user_agent')
        
        if anomaly_features['suspicious_encoding']:
            risk_score += 30
            risk_factors.append('suspicious_encoding')
        
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
    
    def _check_missing_headers(self, headers: Dict) -> List[str]:
        """检查缺失的常见头部"""
        expected_headers = ['host', 'user-agent', 'accept']
        missing = []
        
        for header in expected_headers:
            if header not in [h.lower() for h in headers.keys()]:
                missing.append(header)
        
        return missing
    
    def _check_duplicate_params(self, packet_data: Dict) -> bool:
        """检查重复参数"""
        query_params = packet_data.get('query_params', {})
        post_params = packet_data.get('post_params', {})
        
        # 检查查询参数和POST参数是否有重复
        common_keys = set(query_params.keys()) & set(post_params.keys())
        return len(common_keys) > 0
    
    def _update_statistics(self, ip: str, url: str, current_time: float, packet_data: Dict):
        """更新统计数据"""
        # 更新IP统计
        self.ip_stats[ip]['requests'].append(current_time)
        self.ip_stats[ip]['urls'].add(url)
        
        # 如果有错误指示，记录错误
        if packet_data.get('validation', {}).get('anomalies'):
            self.ip_stats[ip]['errors'].append(current_time)
        
        # 更新URL统计
        self.url_stats[url]['requests'].append(current_time)
        self.url_stats[url]['ips'].add(ip)
        
        # 更新全局统计
        self.global_stats['total_requests'] += 1
    
    def _cleanup_expired_data(self, current_time: float):
        """清理过期数据"""
        cutoff_time = current_time - self.time_window
        
        # 清理IP统计数据
        for ip_data in self.ip_stats.values():
            ip_data['requests'] = deque([t for t in ip_data['requests'] if t > cutoff_time])
            ip_data['errors'] = deque([t for t in ip_data['errors'] if t > cutoff_time])
            
            # 清理会话数据
            for session_id in list(ip_data['sessions'].keys()):
                ip_data['sessions'][session_id] = [
                    t for t in ip_data['sessions'][session_id] if t > cutoff_time
                ]
                if not ip_data['sessions'][session_id]:
                    del ip_data['sessions'][session_id]
        
        # 清理URL统计数据
        for url_data in self.url_stats.values():
            url_data['requests'] = deque([t for t in url_data['requests'] if t > cutoff_time])


# 全局特征提取器实例
_extractor = ContextFeatureExtractor()


# 工作流编排中使用的函数接口
def execute_context_feature_extraction(packet_data: str) -> str:
    """
    工作流编排调用的主函数
    
    Args:
        packet_data: 报文输入模块的输出JSON数据
        
    Returns:
        str: JSON格式的上下文特征数据
    """
    try:
        packet_dict = json.loads(packet_data)
        result = _extractor.extract_features(packet_dict)
        return json.dumps(result, ensure_ascii=False, indent=2)
    except Exception as e:
        error_result = {
            'error': True,
            'error_message': str(e),
            'extraction_timestamp': datetime.now().isoformat()
        }
        return json.dumps(error_result, ensure_ascii=False, indent=2)


# 示例使用代码（用于测试）
if __name__ == "__main__":
    # 模拟报文输入模块的输出
    sample_input = {
        "packet_id": "PKT_1_1705392600",
        "timestamp": "2024-01-15T10:30:00",
        "source_ip": "192.168.1.100",
        "method": "POST",
        "url": "/admin/login.php?debug=1&test=1",
        "headers": {
            "Host": "example.com",
            "User-Agent": "curl/7.68.0",
            "Content-Type": "application/x-www-form-urlencoded"
        },
        "body": "username=admin&password=' OR '1'='1-- ",
        "query_params": {"debug": "1", "test": "1"},
        "post_params": {"username": "admin", "password": "' OR '1'='1-- "},
        "suspicious_patterns": {"post_params": ["sql_injection:or\\s+1\\s*=\\s*1"]}
    }
    
    result = execute_context_feature_extraction(json.dumps(sample_input))
    print("上下文特征提取模块测试结果:")
    print(result)