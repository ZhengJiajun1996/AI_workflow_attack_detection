#!/usr/bin/env python3
"""
网络安全检测智能体 - 独立演示示例
不依赖相对导入的完整演示
"""

import json
import re
import hashlib
import time
from datetime import datetime, timedelta
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Dict, Any, List, Tuple, Optional
from enum import Enum


# ==================== 数据结构定义 ====================

class AttackType(Enum):
    """攻击类型枚举"""
    SQL_INJECTION = "SQL注入"
    XSS = "跨站脚本攻击"
    CSRF = "跨站请求伪造"
    DDOS = "分布式拒绝服务攻击"
    BRUTE_FORCE = "暴力破解"
    DIRECTORY_TRAVERSAL = "目录遍历"
    COMMAND_INJECTION = "命令注入"
    XXE = "XML外部实体注入"
    SSRF = "服务端请求伪造"
    DESERIALIZATION = "反序列化攻击"
    BUFFER_OVERFLOW = "缓冲区溢出"
    WEB_SHELL = "Web Shell上传"
    SCANNER_PROBE = "扫描器探测"
    SUSPICIOUS_FREQUENCY = "可疑频次访问"
    MALICIOUS_USER_AGENT = "恶意User-Agent"
    UNKNOWN = "未知攻击"


class RiskLevel(Enum):
    """风险等级"""
    LOW = "低风险"
    MEDIUM = "中风险"
    HIGH = "高风险"
    CRITICAL = "严重"


@dataclass
class AttackSignature:
    """攻击特征签名"""
    name: str
    attack_type: AttackType
    pattern: str
    description: str
    risk_level: RiskLevel
    confidence: float = 0.0


# ==================== 简化的检测模块 ====================

class SimplePacketProcessor:
    """简化的报文处理器"""
    
    def __init__(self):
        self.packet_count = 0
        
    def process_packet(self, raw_data: str) -> Dict[str, Any]:
        """处理输入报文"""
        self.packet_count += 1
        
        try:
            packet_data = json.loads(raw_data)
            
            result = {
                'packet_id': f"PKT_{self.packet_count}_{int(datetime.now().timestamp())}",
                'timestamp': packet_data.get('timestamp', datetime.now().isoformat()),
                'source_ip': packet_data.get('source_ip', ''),
                'method': packet_data.get('method', ''),
                'url': packet_data.get('url', ''),
                'headers': packet_data.get('headers', {}),
                'body': packet_data.get('body', ''),
                'user_agent': packet_data.get('headers', {}).get('User-Agent', ''),
                'query_params': self._parse_query_params(packet_data.get('url', '')),
                'post_params': self._parse_post_params(packet_data.get('body', '')),
                'suspicious_patterns': self._find_suspicious_patterns(packet_data)
            }
            
            return result
            
        except Exception as e:
            return {'error': True, 'error_message': str(e)}
    
    def _parse_query_params(self, url: str) -> Dict[str, str]:
        """解析URL查询参数"""
        if '?' not in url:
            return {}
        
        query_string = url.split('?', 1)[1]
        params = {}
        for item in query_string.split('&'):
            if '=' in item:
                key, value = item.split('=', 1)
                params[key] = value
        return params
    
    def _parse_post_params(self, body: str) -> Dict[str, str]:
        """解析POST参数"""
        if not body or not body.strip():
            return {}
        
        params = {}
        for item in body.split('&'):
            if '=' in item:
                key, value = item.split('=', 1)
                params[key] = value
        return params
    
    def _find_suspicious_patterns(self, packet_data: Dict) -> Dict[str, List[str]]:
        """查找可疑模式"""
        patterns = {
            'sql_injection': [
                r'union\s+select', r'or\s+1\s*=\s*1', r'and\s+1\s*=\s*1',
                r'drop\s+table', r'insert\s+into', r'delete\s+from'
            ],
            'xss': [
                r'<script[^>]*>', r'javascript:', r'onerror\s*=',
                r'onload\s*=', r'alert\s*\('
            ],
            'command_injection': [
                r';\s*cat\s+', r';\s*ls\s+', r';\s*pwd',
                r'\|\s*nc\s+'
            ]
        }
        
        found_patterns = {}
        test_strings = [
            packet_data.get('url', ''),
            packet_data.get('body', ''),
            str(packet_data.get('headers', {}))
        ]
        
        for category, pattern_list in patterns.items():
            for pattern in pattern_list:
                for test_string in test_strings:
                    if re.search(pattern, test_string, re.IGNORECASE):
                        if category not in found_patterns:
                            found_patterns[category] = []
                        found_patterns[category].append(pattern)
        
        return found_patterns


class SimpleContextExtractor:
    """简化的上下文特征提取器"""
    
    def __init__(self):
        self.ip_stats = defaultdict(lambda: {'requests': [], 'last_seen': 0})
        
    def extract_features(self, packet_data: Dict) -> Dict[str, Any]:
        """提取上下文特征"""
        source_ip = packet_data.get('source_ip', '')
        current_time = time.time()
        
        # 更新IP统计
        self.ip_stats[source_ip]['requests'].append(current_time)
        self.ip_stats[source_ip]['last_seen'] = current_time
        
        # 清理旧数据（保留最近1小时）
        cutoff_time = current_time - 3600
        self.ip_stats[source_ip]['requests'] = [
            t for t in self.ip_stats[source_ip]['requests'] if t > cutoff_time
        ]
        
        # 计算特征
        recent_requests = [
            t for t in self.ip_stats[source_ip]['requests'] 
            if current_time - t <= 300  # 5分钟内
        ]
        
        request_frequency = len(recent_requests) / 5.0
        
        # 检测异常
        anomalies = []
        if request_frequency > 10:
            anomalies.append('high_frequency_requests')
        
        user_agent = packet_data.get('user_agent', '').lower()
        if any(tool in user_agent for tool in ['sqlmap', 'nmap', 'nikto', 'curl']):
            anomalies.append('suspicious_user_agent')
        
        url = packet_data.get('url', '')
        if len(url) > 1000:
            anomalies.append('long_url')
        
        risk_score = 0
        if request_frequency > 20:
            risk_score += 40
        if anomalies:
            risk_score += 30
        if packet_data.get('suspicious_patterns'):
            risk_score += 50
        
        return {
            'ip_features': {
                'request_frequency_5min': request_frequency,
                'total_requests': len(self.ip_stats[source_ip]['requests']),
                'unique_urls_accessed': 1,  # 简化计算
                'error_rate_30min': 0.0
            },
            'time_features': {
                'requests_last_1min': len([t for t in recent_requests if current_time - t <= 60]),
                'requests_last_5min': len(recent_requests),
                'requests_last_1hour': len(self.ip_stats[source_ip]['requests']),
                'is_burst_pattern': request_frequency > 20
            },
            'anomaly_features': {
                'anomalies': anomalies,
                'user_agent_anomalies': ['suspicious_user_agent'] if 'suspicious_user_agent' in anomalies else [],
                'suspicious_encoding': False,
                'large_payload': len(packet_data.get('body', '')) > 10000
            },
            'risk_indicators': {
                'risk_score': min(risk_score, 100),
                'risk_level': self._get_risk_level(risk_score),
                'risk_factors': anomalies,
                'requires_llm_analysis': risk_score >= 50
            }
        }
    
    def _get_risk_level(self, score: int) -> str:
        """根据分数确定风险等级"""
        if score >= 80:
            return '严重'
        elif score >= 60:
            return '高风险'
        elif score >= 40:
            return '中风险'
        else:
            return '低风险'


class SimpleRuleEngine:
    """简化的规则引擎"""
    
    def __init__(self):
        self.scan_count = 0
        self.rules = self._init_rules()
    
    def _init_rules(self):
        """初始化检测规则"""
        return {
            'sql_injection': [
                AttackSignature(
                    name="SQL注入-联合查询",
                    attack_type=AttackType.SQL_INJECTION,
                    pattern=r"union\s+select",
                    description="检测到SQL联合查询注入尝试",
                    risk_level=RiskLevel.HIGH
                ),
                AttackSignature(
                    name="SQL注入-布尔盲注", 
                    attack_type=AttackType.SQL_INJECTION,
                    pattern=r"(and|or)\s+\d+\s*=\s*\d+",
                    description="检测到SQL布尔盲注尝试",
                    risk_level=RiskLevel.HIGH
                )
            ],
            'xss': [
                AttackSignature(
                    name="XSS-脚本标签",
                    attack_type=AttackType.XSS,
                    pattern=r"<script[^>]*>",
                    description="检测到XSS脚本标签注入",
                    risk_level=RiskLevel.HIGH
                )
            ],
            'scanner_probe': [
                AttackSignature(
                    name="扫描器探测",
                    attack_type=AttackType.SCANNER_PROBE,
                    pattern=r"(sqlmap|nmap|nikto|dirb)",
                    description="检测到扫描器探测行为",
                    risk_level=RiskLevel.MEDIUM
                )
            ]
        }
    
    def scan(self, packet_data: Dict, context_data: Dict) -> Dict[str, Any]:
        """执行规则扫描"""
        self.scan_count += 1
        
        matched_signatures = []
        attack_types = []
        evidence = {}
        
        # 构建测试字符串
        test_strings = [
            packet_data.get('url', ''),
            packet_data.get('body', ''),
            packet_data.get('user_agent', ''),
            ' '.join(packet_data.get('query_params', {}).values()),
            ' '.join(packet_data.get('post_params', {}).values())
        ]
        
        # 检查所有规则
        for category, signatures in self.rules.items():
            for signature in signatures:
                for test_string in test_strings:
                    if re.search(signature.pattern, test_string, re.IGNORECASE):
                        signature.confidence = 0.8
                        matched_signatures.append(signature)
                        attack_types.append(signature.attack_type)
                        evidence[category] = {
                            'matched_pattern': signature.pattern,
                            'matched_content': test_string[:100]
                        }
        
        # 基于上下文检测DDoS
        if context_data.get('time_features', {}).get('is_burst_pattern', False):
            ddos_signature = AttackSignature(
                name="DDoS攻击",
                attack_type=AttackType.DDOS,
                pattern="high_frequency",
                description="检测到异常高频请求",
                risk_level=RiskLevel.CRITICAL,
                confidence=0.7
            )
            matched_signatures.append(ddos_signature)
            attack_types.append(AttackType.DDOS)
        
        # 确定最终风险等级
        is_attack = len(matched_signatures) > 0
        if any(sig.risk_level == RiskLevel.CRITICAL for sig in matched_signatures):
            risk_level = '严重'
            confidence = 0.95
        elif any(sig.risk_level == RiskLevel.HIGH for sig in matched_signatures):
            risk_level = '高风险'
            confidence = 0.85
        elif matched_signatures:
            risk_level = '中风险'
            confidence = 0.7
        else:
            risk_level = '低风险'
            confidence = 0.1
        
        return {
            'scan_id': f"SCAN_{self.scan_count}_{int(datetime.now().timestamp())}",
            'is_attack': is_attack,
            'attack_types': [at.value for at in set(attack_types)],
            'risk_level': risk_level,
            'confidence_score': confidence,
            'matched_signatures': [
                {
                    'name': sig.name,
                    'attack_type': sig.attack_type.value,
                    'description': sig.description,
                    'confidence': sig.confidence
                } for sig in matched_signatures
            ],
            'evidence': evidence,
            'requires_llm_analysis': risk_level in ['高风险', '严重'] or len(matched_signatures) > 1
        }


class SimpleLLMAnalyzer:
    """简化的LLM分析器（模拟）"""
    
    def analyze(self, packet_data: Dict, context_data: Dict, rule_result: Dict) -> str:
        """模拟LLM分析"""
        attack_types = rule_result.get('attack_types', [])
        risk_level = rule_result.get('risk_level', '低风险')
        
        if 'SQL注入' in attack_types:
            return """### 威胁概况评估
检测到严重的SQL注入攻击，威胁等级：**严重威胁**
误报概率：5%

### 攻击向量分析  
攻击者使用联合查询（UNION SELECT）技术尝试从数据库中提取敏感信息。
使用了专业的SQL注入工具（如sqlmap），表明攻击者具有一定技术水平。

### 影响评估
如果攻击成功，可能导致：
- 数据库中所有用户凭据泄露
- 管理员账户被盗用
- 整个应用系统被完全控制

### 防护建议
立即措施：
- 立即阻断攻击源IP
- 检查数据库访问日志
- 验证现有用户账户安全性

短期措施：
- 实施SQL查询参数化
- 加强输入验证和过滤
- 启用数据库活动监控"""

        elif 'XSS' in attack_types:
            return """### 威胁概况评估
检测到跨站脚本攻击，威胁等级：**高风险**
误报概率：10%

### 攻击向量分析
攻击者尝试注入JavaScript代码以窃取用户Cookie或执行恶意操作。

### 防护建议
- 启用内容安全策略(CSP)
- 实施严格的输入输出过滤
- 对用户输入进行HTML编码"""

        elif 'DDoS' in attack_types:
            return """### 威胁概况评估
检测到分布式拒绝服务攻击，威胁等级：**严重威胁**
误报概率：15%

### 攻击向量分析
高频率请求攻击，可能是僵尸网络发起的协调攻击。

### 防护建议
- 启用流量清洗和限流
- 实施IP黑名单机制
- 扩展服务器处理能力"""

        else:
            return """### 威胁概况评估
经过深度分析，确认为正常的用户请求，威胁等级：**无威胁**
误报概率：2%

### 建议
继续正常监控，无需特殊处置。"""


class SimpleResponseGenerator:
    """简化的响应生成器"""
    
    def generate_response(self, packet_data: Dict, context_data: Dict, 
                         rule_result: Dict, llm_analysis: str) -> Dict[str, Any]:
        """生成安全响应"""
        
        is_attack = rule_result.get('is_attack', False)
        risk_level = rule_result.get('risk_level', '低风险')
        attack_types = rule_result.get('attack_types', [])
        
        # 确定响应动作
        if risk_level == '严重':
            action = {
                'action': 'block_immediately',
                'description': '立即阻断IP地址和请求',
                'priority': 'critical'
            }
        elif risk_level == '高风险':
            action = {
                'action': 'block_and_alert', 
                'description': '阻断请求并生成高优先级告警',
                'priority': 'high'
            }
        elif risk_level == '中风险':
            action = {
                'action': 'alert_and_monitor',
                'description': '生成告警并加强监控',
                'priority': 'medium'
            }
        else:
            action = {
                'action': 'allow_and_log',
                'description': '允许请求通过并记录日志',
                'priority': 'low'
            }
        
        # 生成执行摘要
        if is_attack:
            if len(attack_types) == 1:
                attack_desc = attack_types[0]
            else:
                attack_desc = f"多种攻击类型（{', '.join(attack_types[:2])}等）"
            
            summary = (f"检测到来自 {packet_data.get('source_ip', 'unknown')} 的{attack_desc}攻击，"
                      f"威胁等级：{risk_level}，置信度：{rule_result.get('confidence_score', 0):.1%}")
        else:
            summary = f"检测到来自 {packet_data.get('source_ip', 'unknown')} 的正常HTTP请求，未发现威胁"
        
        # 生成防护建议
        recommendations = []
        if 'SQL注入' in attack_types:
            recommendations.extend([
                '立即阻断该IP地址',
                '检查应用程序的SQL查询参数化',
                '审计数据库访问日志'
            ])
        elif 'XSS' in attack_types:
            recommendations.extend([
                '阻断请求并记录日志',
                '检查输入输出过滤机制',
                '启用内容安全策略(CSP)'
            ])
        elif 'DDoS' in attack_types:
            recommendations.extend([
                '启用流量清洗',
                '实施IP限频策略',
                '联系ISP进行上游过滤'
            ])
        else:
            recommendations = ['继续正常监控']
        
        return {
            'response_id': f"RESP_{int(datetime.now().timestamp())}",
            'timestamp': datetime.now().isoformat(),
            'threat_assessment': {
                'is_malicious': is_attack,
                'threat_level': risk_level,
                'confidence_score': rule_result.get('confidence_score', 0),
                'attack_types': attack_types
            },
            'response_action': action,
            'executive_summary': summary,
            'llm_analysis': llm_analysis,
            'protection_recommendations': {
                'immediate': recommendations[:3],
                'short_term': ['更新安全规则', '加强监控'],
                'long_term': ['安全培训', '系统加固']
            }
        }


# ==================== 演示主类 ====================

class NetworkSecurityAgentDemo:
    """网络安全检测智能体演示"""
    
    def __init__(self):
        self.packet_processor = SimplePacketProcessor()
        self.context_extractor = SimpleContextExtractor()
        self.rule_engine = SimpleRuleEngine()
        self.llm_analyzer = SimpleLLMAnalyzer()
        self.response_generator = SimpleResponseGenerator()
        self.demo_cases = self._prepare_demo_cases()
    
    def _prepare_demo_cases(self):
        """准备演示用例"""
        return [
            {
                "name": "SQL注入攻击",
                "description": "典型的SQL注入攻击尝试",
                "input_data": {
                    "timestamp": "2024-01-15T10:30:00Z",
                    "source_ip": "192.168.1.100",
                    "method": "POST",
                    "url": "/admin/login.php?id=1' UNION SELECT user,password FROM users--",
                    "headers": {
                        "Host": "vulnerable-site.com",
                        "User-Agent": "sqlmap/1.6.12#dev (http://sqlmap.org)",
                        "Content-Type": "application/x-www-form-urlencoded"
                    },
                    "body": "username=admin&password=' OR '1'='1'-- "
                }
            },
            {
                "name": "XSS攻击",
                "description": "跨站脚本攻击尝试", 
                "input_data": {
                    "timestamp": "2024-01-15T10:35:00Z",
                    "source_ip": "203.0.113.45",
                    "method": "GET",
                    "url": "/search.php?q=<script>alert('XSS')</script>",
                    "headers": {
                        "Host": "vulnerable-site.com",
                        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
                    },
                    "body": ""
                }
            },
            {
                "name": "DDoS攻击模拟",
                "description": "高频请求模拟DDoS攻击",
                "input_data": {
                    "timestamp": "2024-01-15T10:40:00Z",
                    "source_ip": "198.51.100.10",
                    "method": "GET",
                    "url": "/index.html",
                    "headers": {
                        "Host": "target-site.com",
                        "User-Agent": "Mozilla/5.0"
                    },
                    "body": ""
                },
                "simulate_high_frequency": True
            },
            {
                "name": "正常请求",
                "description": "正常的用户请求",
                "input_data": {
                    "timestamp": "2024-01-15T10:45:00Z",
                    "source_ip": "192.168.1.50",
                    "method": "GET",
                    "url": "/products/laptop-dell-xps13",
                    "headers": {
                        "Host": "ecommerce-site.com",
                        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
                        "Referer": "https://ecommerce-site.com/search?q=laptop"
                    },
                    "body": ""
                }
            }
        ]
    
    def run_complete_demo(self):
        """运行完整演示"""
        print("=" * 80)
        print("网络安全检测智能体 - 完整演示")
        print("=" * 80)
        print()
        
        for i, case in enumerate(self.demo_cases, 1):
            print(f"演示案例 {i}: {case['name']}")
            print(f"描述: {case['description']}")
            print("-" * 60)
            
            try:
                result = self._execute_detection_workflow(case)
                self._display_result_summary(result)
                
            except Exception as e:
                print(f"❌ 执行失败: {str(e)}")
            
            print("\n" + "=" * 80 + "\n")
    
    def _execute_detection_workflow(self, case):
        """执行完整的检测工作流"""
        print("🔄 开始执行检测工作流...")
        
        # 1. 报文输入处理
        print("📥 步骤1: 报文输入处理...")
        packet_data = self.packet_processor.process_packet(json.dumps(case['input_data']))
        
        if packet_data.get('error'):
            raise Exception(f"报文处理失败: {packet_data.get('error_message')}")
        
        print(f"   ✅ 报文ID: {packet_data.get('packet_id')}")
        print(f"   ✅ 源IP: {packet_data.get('source_ip')}")
        print(f"   ✅ 请求: {packet_data.get('method')} {packet_data.get('url')[:50]}...")
        
        # 2. 上下文特征提取
        print("🔍 步骤2: 上下文特征提取...")
        
        # 模拟高频请求
        if case.get('simulate_high_frequency'):
            # 模拟多次请求以触发高频检测
            for _ in range(25):
                self.context_extractor.extract_features(packet_data)
        
        context_data = self.context_extractor.extract_features(packet_data)
        
        risk_score = context_data.get('risk_indicators', {}).get('risk_score', 0)
        print(f"   ✅ 风险评分: {risk_score}/100")
        print(f"   ✅ 请求频率: {context_data.get('ip_features', {}).get('request_frequency_5min', 0):.1f} 次/分钟")
        
        # 3. 规则引擎扫描
        print("🛡️ 步骤3: 规则引擎扫描...")
        rule_result = self.rule_engine.scan(packet_data, context_data)
        
        is_attack = rule_result.get('is_attack', False)
        risk_level = rule_result.get('risk_level', '低风险')
        confidence = rule_result.get('confidence_score', 0.0)
        
        print(f"   ✅ 攻击检测: {'是' if is_attack else '否'}")
        print(f"   ✅ 风险等级: {risk_level}")
        print(f"   ✅ 置信度: {confidence:.1%}")
        
        if rule_result.get('attack_types'):
            print(f"   ✅ 攻击类型: {', '.join(rule_result.get('attack_types', []))}")
        
        # 4. LLM深度分析
        requires_llm = rule_result.get('requires_llm_analysis', False)
        llm_analysis = ""
        
        if requires_llm:
            print("🤖 步骤4: LLM深度分析...")
            llm_analysis = self.llm_analyzer.analyze(packet_data, context_data, rule_result)
            print(f"   ✅ LLM分析完成")
            print(f"   ✅ 分析长度: {len(llm_analysis)} 字符")
        else:
            print("ℹ️ 步骤4: 跳过LLM分析（风险等级较低）")
            llm_analysis = "风险等级较低，无需深度分析"
        
        # 5. 生成安全响应
        print("📋 步骤5: 生成安全响应...")
        response_data = self.response_generator.generate_response(
            packet_data, context_data, rule_result, llm_analysis
        )
        
        print("   ✅ 安全响应生成完成")
        
        return {
            'packet_data': packet_data,
            'context_data': context_data,
            'rule_result': rule_result,
            'llm_analysis': llm_analysis,
            'response_data': response_data
        }
    
    def _display_result_summary(self, result):
        """显示结果摘要"""
        response_data = result['response_data']
        threat_assessment = response_data.get('threat_assessment', {})
        
        print("\n📊 检测结果摘要:")
        print(f"   响应ID: {response_data.get('response_id')}")
        print(f"   是否恶意: {'是' if threat_assessment.get('is_malicious') else '否'}")
        print(f"   威胁等级: {threat_assessment.get('threat_level', '未知')}")
        print(f"   置信度: {threat_assessment.get('confidence_score', 0):.1%}")
        
        if threat_assessment.get('attack_types'):
            print(f"   攻击类型: {', '.join(threat_assessment.get('attack_types', []))}")
        
        # 显示响应动作
        response_action = response_data.get('response_action', {})
        print(f"\n🎯 响应动作:")
        print(f"   动作: {response_action.get('description', '未知')}")
        print(f"   优先级: {response_action.get('priority', '未知')}")
        
        # 显示执行摘要
        executive_summary = response_data.get('executive_summary', '')
        if executive_summary:
            print(f"\n📋 执行摘要:")
            print(f"   {executive_summary}")
        
        # 显示防护建议
        protection_recs = response_data.get('protection_recommendations', {})
        immediate_actions = protection_recs.get('immediate', [])
        if immediate_actions:
            print(f"\n🛡️ 立即防护措施:")
            for action in immediate_actions:
                print(f"   • {action}")
        
        # 显示LLM分析摘要
        llm_analysis = result.get('llm_analysis', '')
        if llm_analysis and len(llm_analysis) > 100:
            print(f"\n🤖 LLM分析摘要:")
            # 提取第一段作为摘要
            first_section = llm_analysis.split('\n\n')[0] if '\n\n' in llm_analysis else llm_analysis[:200]
            print(f"   {first_section}...")


def main():
    """主函数"""
    demo = NetworkSecurityAgentDemo()
    demo.run_complete_demo()


if __name__ == "__main__":
    main()