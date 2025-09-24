"""
网络安全检测智能体 - 规则引擎与扫描函数模块
工作流编排中的Python代码模块
"""
import json
import re
import base64
import urllib.parse
from datetime import datetime
from typing import Dict, Any, List, Tuple, Optional
from ..utils.data_structures import AttackType, RiskLevel, AttackSignature, DetectionResult


class RuleEngineScanner:
    """规则引擎扫描器 - 内置多种常见互联网攻击类型专家检测规则"""
    
    def __init__(self):
        self.attack_rules = self._initialize_attack_rules()
        self.scan_count = 0
        
    def scan_packet(self, packet_data: Dict[str, Any], context_features: Dict[str, Any]) -> Dict[str, Any]:
        """
        扫描报文和上下文特征，检测攻击
        
        Args:
            packet_data: 报文输入模块的输出
            context_features: 上下文特征提取模块的输出
            
        Returns:
            Dict: 检测结果
        """
        try:
            self.scan_count += 1
            
            # 初始化检测结果
            detection_result = DetectionResult(
                is_attack=False,
                attack_types=[],
                risk_level=RiskLevel.LOW,
                confidence_score=0.0,
                matched_signatures=[],
                suspicious_features=[],
                evidence={},
                recommendations=[]
            )
            
            # 执行各类攻击检测
            self._detect_sql_injection(packet_data, context_features, detection_result)
            self._detect_xss_attacks(packet_data, context_features, detection_result)
            self._detect_command_injection(packet_data, context_features, detection_result)
            self._detect_directory_traversal(packet_data, context_features, detection_result)
            self._detect_xxe_attacks(packet_data, context_features, detection_result)
            self._detect_ssrf_attacks(packet_data, context_features, detection_result)
            self._detect_deserialization_attacks(packet_data, context_features, detection_result)
            self._detect_web_shell_upload(packet_data, context_features, detection_result)
            self._detect_scanner_probes(packet_data, context_features, detection_result)
            self._detect_brute_force_attacks(packet_data, context_features, detection_result)
            self._detect_ddos_attacks(packet_data, context_features, detection_result)
            self._detect_csrf_attacks(packet_data, context_features, detection_result)
            
            # 基于上下文特征的异常检测
            self._detect_frequency_anomalies(context_features, detection_result)
            self._detect_behavioral_anomalies(context_features, detection_result)
            
            # 计算最终风险等级和置信度
            self._calculate_final_risk_assessment(detection_result)
            
            # 生成防护建议
            self._generate_recommendations(detection_result)
            
            # 构建返回结果
            result = {
                'scan_id': f"SCAN_{self.scan_count}_{int(datetime.now().timestamp())}",
                'scan_timestamp': datetime.now().isoformat(),
                'packet_id': packet_data.get('packet_id', ''),
                'is_attack': detection_result.is_attack,
                'attack_types': [at.value for at in detection_result.attack_types],
                'risk_level': detection_result.risk_level.value,
                'confidence_score': detection_result.confidence_score,
                'matched_signatures': [
                    {
                        'name': sig.name,
                        'attack_type': sig.attack_type.value,
                        'description': sig.description,
                        'confidence': sig.confidence
                    } for sig in detection_result.matched_signatures
                ],
                'suspicious_features': detection_result.suspicious_features,
                'evidence': detection_result.evidence,
                'recommendations': detection_result.recommendations,
                'requires_llm_analysis': self._requires_llm_analysis(detection_result, context_features)
            }
            
            return result
            
        except Exception as e:
            return {
                'error': True,
                'error_message': str(e),
                'scan_id': f"ERR_SCAN_{self.scan_count}_{int(datetime.now().timestamp())}",
                'scan_timestamp': datetime.now().isoformat()
            }
    
    def _initialize_attack_rules(self) -> Dict[str, List[AttackSignature]]:
        """初始化攻击检测规则"""
        rules = {
            'sql_injection': [
                AttackSignature(
                    name="SQL注入-联合查询",
                    attack_type=AttackType.SQL_INJECTION,
                    pattern=r"union\s+select|union\s+all\s+select",
                    description="检测到SQL联合查询注入尝试",
                    risk_level=RiskLevel.HIGH
                ),
                AttackSignature(
                    name="SQL注入-布尔盲注",
                    attack_type=AttackType.SQL_INJECTION,
                    pattern=r"(and|or)\s+\d+\s*=\s*\d+|'\s*(and|or)\s+'[^']*'\s*=\s*'[^']*'",
                    description="检测到SQL布尔盲注尝试",
                    risk_level=RiskLevel.HIGH
                ),
                AttackSignature(
                    name="SQL注入-注释绕过",
                    attack_type=AttackType.SQL_INJECTION,
                    pattern=r"--\s|#|\*/|/\*",
                    description="检测到SQL注释绕过尝试",
                    risk_level=RiskLevel.MEDIUM
                ),
                AttackSignature(
                    name="SQL注入-堆叠查询",
                    attack_type=AttackType.SQL_INJECTION,
                    pattern=r";\s*(drop|insert|delete|update|create|alter)\s+",
                    description="检测到SQL堆叠查询注入",
                    risk_level=RiskLevel.CRITICAL
                )
            ],
            'xss': [
                AttackSignature(
                    name="XSS-脚本标签",
                    attack_type=AttackType.XSS,
                    pattern=r"<script[^>]*>.*?</script>|<script[^>]*/>",
                    description="检测到XSS脚本标签注入",
                    risk_level=RiskLevel.HIGH
                ),
                AttackSignature(
                    name="XSS-事件处理器",
                    attack_type=AttackType.XSS,
                    pattern=r"on(load|error|click|mouseover|focus|blur)\s*=",
                    description="检测到XSS事件处理器注入",
                    risk_level=RiskLevel.HIGH
                ),
                AttackSignature(
                    name="XSS-JavaScript协议",
                    attack_type=AttackType.XSS,
                    pattern=r"javascript:|vbscript:|data:text/html",
                    description="检测到XSS伪协议注入",
                    risk_level=RiskLevel.MEDIUM
                ),
                AttackSignature(
                    name="XSS-编码绕过",
                    attack_type=AttackType.XSS,
                    pattern=r"&#x?[0-9a-f]+;|%[0-9a-f]{2}|\\x[0-9a-f]{2}",
                    description="检测到XSS编码绕过尝试",
                    risk_level=RiskLevel.MEDIUM
                )
            ],
            'command_injection': [
                AttackSignature(
                    name="命令注入-系统命令",
                    attack_type=AttackType.COMMAND_INJECTION,
                    pattern=r";\s*(cat|ls|pwd|id|whoami|uname|ps|netstat)\s|`(cat|ls|pwd|id|whoami)",
                    description="检测到系统命令注入尝试",
                    risk_level=RiskLevel.HIGH
                ),
                AttackSignature(
                    name="命令注入-管道符",
                    attack_type=AttackType.COMMAND_INJECTION,
                    pattern=r"\|\s*(nc|curl|wget|python|perl|ruby|php)",
                    description="检测到管道符命令注入",
                    risk_level=RiskLevel.HIGH
                ),
                AttackSignature(
                    name="命令注入-反引号",
                    attack_type=AttackType.COMMAND_INJECTION,
                    pattern=r"`[^`]*`|\$\([^)]*\)",
                    description="检测到反引号命令执行",
                    risk_level=RiskLevel.MEDIUM
                )
            ],
            'directory_traversal': [
                AttackSignature(
                    name="目录遍历-相对路径",
                    attack_type=AttackType.DIRECTORY_TRAVERSAL,
                    pattern=r"\.\./|\.\.\\\|%2e%2e%2f|%2e%2e%5c",
                    description="检测到目录遍历攻击",
                    risk_level=RiskLevel.MEDIUM
                ),
                AttackSignature(
                    name="目录遍历-敏感文件",
                    attack_type=AttackType.DIRECTORY_TRAVERSAL,
                    pattern=r"/etc/passwd|/etc/shadow|win\.ini|boot\.ini",
                    description="检测到敏感文件访问尝试",
                    risk_level=RiskLevel.HIGH
                )
            ]
        }
        return rules
    
    def _detect_sql_injection(self, packet_data: Dict, context_features: Dict, result: DetectionResult):
        """检测SQL注入攻击"""
        test_strings = [
            packet_data.get('url', ''),
            packet_data.get('body', ''),
            ' '.join(packet_data.get('query_params', {}).values()),
            ' '.join(packet_data.get('post_params', {}).values())
        ]
        
        for rule in self.attack_rules.get('sql_injection', []):
            for test_string in test_strings:
                if re.search(rule.pattern, test_string, re.IGNORECASE):
                    rule.confidence = 0.8
                    result.matched_signatures.append(rule)
                    result.attack_types.append(AttackType.SQL_INJECTION)
                    result.is_attack = True
                    result.evidence['sql_injection'] = {
                        'matched_pattern': rule.pattern,
                        'matched_content': test_string[:200],
                        'rule_name': rule.name
                    }
    
    def _detect_xss_attacks(self, packet_data: Dict, context_features: Dict, result: DetectionResult):
        """检测XSS攻击"""
        test_strings = [
            packet_data.get('url', ''),
            packet_data.get('body', ''),
            ' '.join(packet_data.get('query_params', {}).values()),
            ' '.join(packet_data.get('post_params', {}).values()),
            ' '.join(packet_data.get('headers', {}).values())
        ]
        
        for rule in self.attack_rules.get('xss', []):
            for test_string in test_strings:
                # URL解码后再检测
                decoded_string = urllib.parse.unquote(test_string)
                if re.search(rule.pattern, decoded_string, re.IGNORECASE | re.DOTALL):
                    rule.confidence = 0.75
                    result.matched_signatures.append(rule)
                    result.attack_types.append(AttackType.XSS)
                    result.is_attack = True
                    result.evidence['xss'] = {
                        'matched_pattern': rule.pattern,
                        'matched_content': decoded_string[:200],
                        'rule_name': rule.name
                    }
    
    def _detect_command_injection(self, packet_data: Dict, context_features: Dict, result: DetectionResult):
        """检测命令注入攻击"""
        test_strings = [
            packet_data.get('url', ''),
            packet_data.get('body', ''),
            ' '.join(packet_data.get('query_params', {}).values()),
            ' '.join(packet_data.get('post_params', {}).values())
        ]
        
        for rule in self.attack_rules.get('command_injection', []):
            for test_string in test_strings:
                if re.search(rule.pattern, test_string, re.IGNORECASE):
                    rule.confidence = 0.85
                    result.matched_signatures.append(rule)
                    result.attack_types.append(AttackType.COMMAND_INJECTION)
                    result.is_attack = True
                    result.evidence['command_injection'] = {
                        'matched_pattern': rule.pattern,
                        'matched_content': test_string[:200],
                        'rule_name': rule.name
                    }
    
    def _detect_directory_traversal(self, packet_data: Dict, context_features: Dict, result: DetectionResult):
        """检测目录遍历攻击"""
        url = packet_data.get('url', '')
        body = packet_data.get('body', '')
        
        for rule in self.attack_rules.get('directory_traversal', []):
            test_content = f"{url} {body}"
            if re.search(rule.pattern, test_content, re.IGNORECASE):
                rule.confidence = 0.7
                result.matched_signatures.append(rule)
                result.attack_types.append(AttackType.DIRECTORY_TRAVERSAL)
                result.is_attack = True
                result.evidence['directory_traversal'] = {
                    'matched_pattern': rule.pattern,
                    'matched_content': test_content[:200],
                    'rule_name': rule.name
                }
    
    def _detect_xxe_attacks(self, packet_data: Dict, context_features: Dict, result: DetectionResult):
        """检测XXE攻击"""
        body = packet_data.get('body', '')
        content_type = packet_data.get('headers', {}).get('Content-Type', '')
        
        if 'xml' in content_type.lower() or body.strip().startswith('<?xml'):
            xxe_patterns = [
                r'<!ENTITY.*>',
                r'SYSTEM\s+["\']file://',
                r'SYSTEM\s+["\']http://',
                r'<!DOCTYPE.*\[.*<!ENTITY'
            ]
            
            for pattern in xxe_patterns:
                if re.search(pattern, body, re.IGNORECASE | re.DOTALL):
                    signature = AttackSignature(
                        name="XXE外部实体注入",
                        attack_type=AttackType.XXE,
                        pattern=pattern,
                        description="检测到XXE外部实体注入尝试",
                        risk_level=RiskLevel.HIGH,
                        confidence=0.8
                    )
                    result.matched_signatures.append(signature)
                    result.attack_types.append(AttackType.XXE)
                    result.is_attack = True
                    result.evidence['xxe'] = {
                        'matched_pattern': pattern,
                        'matched_content': body[:300]
                    }
    
    def _detect_ssrf_attacks(self, packet_data: Dict, context_features: Dict, result: DetectionResult):
        """检测SSRF攻击"""
        test_strings = [
            packet_data.get('url', ''),
            packet_data.get('body', ''),
            ' '.join(packet_data.get('query_params', {}).values()),
            ' '.join(packet_data.get('post_params', {}).values())
        ]
        
        ssrf_patterns = [
            r'https?://127\.0\.0\.1',
            r'https?://localhost',
            r'https?://0\.0\.0\.0',
            r'https?://\[::1\]',
            r'https?://169\.254\.169\.254',  # AWS metadata
            r'file://',
            r'gopher://',
            r'dict://'
        ]
        
        for pattern in ssrf_patterns:
            for test_string in test_strings:
                if re.search(pattern, test_string, re.IGNORECASE):
                    signature = AttackSignature(
                        name="SSRF服务端请求伪造",
                        attack_type=AttackType.SSRF,
                        pattern=pattern,
                        description="检测到SSRF攻击尝试",
                        risk_level=RiskLevel.HIGH,
                        confidence=0.75
                    )
                    result.matched_signatures.append(signature)
                    result.attack_types.append(AttackType.SSRF)
                    result.is_attack = True
                    result.evidence['ssrf'] = {
                        'matched_pattern': pattern,
                        'matched_content': test_string[:200]
                    }
    
    def _detect_deserialization_attacks(self, packet_data: Dict, context_features: Dict, result: DetectionResult):
        """检测反序列化攻击"""
        body = packet_data.get('body', '')
        headers = packet_data.get('headers', {})
        
        # 检测Java反序列化
        if body and (body.startswith('aced0005') or 'java.lang' in body or 'ObjectInputStream' in body):
            signature = AttackSignature(
                name="Java反序列化攻击",
                attack_type=AttackType.DESERIALIZATION,
                pattern="java_deserialization",
                description="检测到Java反序列化攻击",
                risk_level=RiskLevel.HIGH,
                confidence=0.8
            )
            result.matched_signatures.append(signature)
            result.attack_types.append(AttackType.DESERIALIZATION)
            result.is_attack = True
    
    def _detect_web_shell_upload(self, packet_data: Dict, context_features: Dict, result: DetectionResult):
        """检测Web Shell上传"""
        body = packet_data.get('body', '')
        content_type = packet_data.get('headers', {}).get('Content-Type', '')
        
        if 'multipart/form-data' in content_type:
            webshell_patterns = [
                r'eval\s*\(\s*\$_POST',
                r'system\s*\(\s*\$_GET',
                r'exec\s*\(\s*\$_REQUEST',
                r'passthru\s*\(',
                r'shell_exec\s*\(',
                r'<%.*eval.*%>',
                r'<\?php.*system.*\?>'
            ]
            
            for pattern in webshell_patterns:
                if re.search(pattern, body, re.IGNORECASE):
                    signature = AttackSignature(
                        name="Web Shell上传",
                        attack_type=AttackType.WEB_SHELL,
                        pattern=pattern,
                        description="检测到Web Shell上传尝试",
                        risk_level=RiskLevel.CRITICAL,
                        confidence=0.9
                    )
                    result.matched_signatures.append(signature)
                    result.attack_types.append(AttackType.WEB_SHELL)
                    result.is_attack = True
    
    def _detect_scanner_probes(self, packet_data: Dict, context_features: Dict, result: DetectionResult):
        """检测扫描器探测"""
        user_agent = packet_data.get('user_agent', '').lower()
        url = packet_data.get('url', '')
        
        scanner_signatures = [
            'nmap', 'masscan', 'zmap', 'nikto', 'dirb', 'gobuster',
            'sqlmap', 'burpsuite', 'owasp zap', 'w3af', 'acunetix',
            'nessus', 'openvas', 'metasploit'
        ]
        
        for scanner in scanner_signatures:
            if scanner in user_agent:
                signature = AttackSignature(
                    name="扫描器探测",
                    attack_type=AttackType.SCANNER_PROBE,
                    pattern=scanner,
                    description=f"检测到{scanner}扫描器探测",
                    risk_level=RiskLevel.MEDIUM,
                    confidence=0.95
                )
                result.matched_signatures.append(signature)
                result.attack_types.append(AttackType.SCANNER_PROBE)
                result.is_attack = True
        
        # 检测扫描器常见路径
        scanner_paths = [
            '/admin', '/phpmyadmin', '/wp-admin', '/.git', '/.svn',
            '/config', '/backup', '/test', '/robots.txt', '/sitemap.xml'
        ]
        
        for path in scanner_paths:
            if path in url:
                result.suspicious_features.append(f"扫描器常见路径: {path}")
    
    def _detect_brute_force_attacks(self, packet_data: Dict, context_features: Dict, result: DetectionResult):
        """检测暴力破解攻击"""
        url = packet_data.get('url', '').lower()
        method = packet_data.get('method', '')
        
        # 检测登录相关的暴力破解
        if method == 'POST' and any(keyword in url for keyword in ['login', 'signin', 'auth', 'admin']):
            ip_features = context_features.get('ip_features', {})
            time_features = context_features.get('time_features', {})
            
            # 基于频率判断
            if (ip_features.get('request_frequency_5min', 0) > 30 and
                time_features.get('requests_last_1min', 0) > 10):
                
                signature = AttackSignature(
                    name="暴力破解攻击",
                    attack_type=AttackType.BRUTE_FORCE,
                    pattern="high_frequency_login",
                    description="检测到高频登录尝试，疑似暴力破解",
                    risk_level=RiskLevel.HIGH,
                    confidence=0.7
                )
                result.matched_signatures.append(signature)
                result.attack_types.append(AttackType.BRUTE_FORCE)
                result.is_attack = True
    
    def _detect_ddos_attacks(self, packet_data: Dict, context_features: Dict, result: DetectionResult):
        """检测DDoS攻击"""
        time_features = context_features.get('time_features', {})
        
        # 基于请求频率判断DDoS
        if (time_features.get('requests_last_1min', 0) > 100 or
            time_features.get('requests_last_5min', 0) > 300):
            
            signature = AttackSignature(
                name="DDoS攻击",
                attack_type=AttackType.DDOS,
                pattern="high_frequency_requests",
                description="检测到异常高频请求，疑似DDoS攻击",
                risk_level=RiskLevel.CRITICAL,
                confidence=0.6
            )
            result.matched_signatures.append(signature)
            result.attack_types.append(AttackType.DDOS)
            result.is_attack = True
    
    def _detect_csrf_attacks(self, packet_data: Dict, context_features: Dict, result: DetectionResult):
        """检测CSRF攻击"""
        method = packet_data.get('method', '')
        headers = packet_data.get('headers', {})
        referer = headers.get('Referer', '')
        
        if method in ['POST', 'PUT', 'DELETE']:
            # 检查是否缺少CSRF防护
            if not any(header.lower().startswith('x-csrf') for header in headers.keys()):
                # 检查Referer头
                if not referer or 'javascript:' in referer:
                    result.suspicious_features.append("可能的CSRF攻击：缺少防护token且Referer异常")
    
    def _detect_frequency_anomalies(self, context_features: Dict, result: DetectionResult):
        """基于上下文特征检测频率异常"""
        risk_indicators = context_features.get('risk_indicators', {})
        
        if risk_indicators.get('risk_score', 0) >= 60:
            signature = AttackSignature(
                name="频率异常检测",
                attack_type=AttackType.SUSPICIOUS_FREQUENCY,
                pattern="context_analysis",
                description="基于上下文特征检测到异常行为模式",
                risk_level=RiskLevel.MEDIUM,
                confidence=risk_indicators.get('risk_score', 0) / 100
            )
            result.matched_signatures.append(signature)
            result.attack_types.append(AttackType.SUSPICIOUS_FREQUENCY)
            result.suspicious_features.extend(risk_indicators.get('risk_factors', []))
    
    def _detect_behavioral_anomalies(self, context_features: Dict, result: DetectionResult):
        """检测行为异常"""
        anomaly_features = context_features.get('anomaly_features', {})
        
        if anomaly_features.get('user_agent_anomalies'):
            result.suspicious_features.append("User-Agent异常")
            
        if anomaly_features.get('suspicious_encoding'):
            result.suspicious_features.append("可疑编码模式")
            
        if anomaly_features.get('unusual_header_count', 0) > 5:
            result.suspicious_features.append("异常HTTP头部")
    
    def _calculate_final_risk_assessment(self, result: DetectionResult):
        """计算最终风险评估"""
        if not result.is_attack:
            result.risk_level = RiskLevel.LOW
            result.confidence_score = 0.0
            return
        
        # 基于匹配的签名计算风险等级
        critical_count = sum(1 for sig in result.matched_signatures if sig.risk_level == RiskLevel.CRITICAL)
        high_count = sum(1 for sig in result.matched_signatures if sig.risk_level == RiskLevel.HIGH)
        medium_count = sum(1 for sig in result.matched_signatures if sig.risk_level == RiskLevel.MEDIUM)
        
        if critical_count > 0:
            result.risk_level = RiskLevel.CRITICAL
            result.confidence_score = 0.95
        elif high_count > 0:
            result.risk_level = RiskLevel.HIGH
            result.confidence_score = 0.8
        elif medium_count > 1:
            result.risk_level = RiskLevel.HIGH
            result.confidence_score = 0.7
        elif medium_count > 0:
            result.risk_level = RiskLevel.MEDIUM
            result.confidence_score = 0.6
        else:
            result.risk_level = RiskLevel.LOW
            result.confidence_score = 0.3
    
    def _generate_recommendations(self, result: DetectionResult):
        """生成防护建议"""
        if not result.is_attack:
            result.recommendations = ["请求正常，继续监控"]
            return
        
        recommendations = []
        
        for attack_type in set(result.attack_types):
            if attack_type == AttackType.SQL_INJECTION:
                recommendations.extend([
                    "立即阻断该IP地址",
                    "检查应用程序的SQL查询参数化",
                    "启用WAF SQL注入防护规则",
                    "审计数据库访问日志"
                ])
            elif attack_type == AttackType.XSS:
                recommendations.extend([
                    "阻断请求并记录日志",
                    "检查输入输出过滤机制",
                    "启用内容安全策略(CSP)",
                    "对用户输入进行HTML编码"
                ])
            elif attack_type == AttackType.COMMAND_INJECTION:
                recommendations.extend([
                    "立即阻断并告警",
                    "检查系统命令执行接口",
                    "限制应用程序权限",
                    "启用系统调用监控"
                ])
            elif attack_type == AttackType.DDOS:
                recommendations.extend([
                    "启用流量清洗",
                    "实施IP限频策略",
                    "联系ISP进行上游过滤",
                    "扩展服务器资源"
                ])
            elif attack_type == AttackType.BRUTE_FORCE:
                recommendations.extend([
                    "临时锁定该IP",
                    "启用账户锁定机制",
                    "实施验证码验证",
                    "监控异常登录尝试"
                ])
            elif attack_type == AttackType.WEB_SHELL:
                recommendations.extend([
                    "立即阻断上传",
                    "扫描服务器文件系统",
                    "检查上传文件类型限制",
                    "隔离受影响服务器"
                ])
        
        # 去重并限制数量
        result.recommendations = list(set(recommendations))[:8]
    
    def _requires_llm_analysis(self, result: DetectionResult, context_features: Dict) -> bool:
        """判断是否需要LLM深度分析"""
        # 高风险或严重风险需要LLM分析
        if result.risk_level in [RiskLevel.HIGH, RiskLevel.CRITICAL]:
            return True
        
        # 上下文特征异常需要LLM分析
        if context_features.get('risk_indicators', {}).get('requires_llm_analysis', False):
            return True
        
        # 多种攻击类型并发需要LLM分析
        if len(set(result.attack_types)) > 2:
            return True
        
        # 可疑特征较多需要LLM分析
        if len(result.suspicious_features) > 3:
            return True
        
        return False


# 全局扫描器实例
_scanner = RuleEngineScanner()


# 工作流编排中使用的函数接口
def execute_rule_engine_scan(packet_data: str, context_features: str) -> str:
    """
    工作流编排调用的主函数
    
    Args:
        packet_data: 报文输入模块的输出JSON数据
        context_features: 上下文特征提取模块的输出JSON数据
        
    Returns:
        str: JSON格式的扫描检测结果
    """
    try:
        packet_dict = json.loads(packet_data)
        context_dict = json.loads(context_features)
        
        result = _scanner.scan_packet(packet_dict, context_dict)
        return json.dumps(result, ensure_ascii=False, indent=2)
    except Exception as e:
        error_result = {
            'error': True,
            'error_message': str(e),
            'scan_timestamp': datetime.now().isoformat()
        }
        return json.dumps(error_result, ensure_ascii=False, indent=2)


# 示例使用代码（用于测试）
if __name__ == "__main__":
    # 测试用例
    sample_packet = {
        "packet_id": "PKT_1_1705392600",
        "url": "/admin/login.php?id=1' UNION SELECT user,pass FROM admin--",
        "method": "POST",
        "body": "username=admin&password=' OR '1'='1-- ",
        "headers": {"User-Agent": "sqlmap/1.6.12"},
        "query_params": {"id": "1' UNION SELECT user,pass FROM admin--"},
        "post_params": {"username": "admin", "password": "' OR '1'='1-- "}
    }
    
    sample_context = {
        "ip_features": {"request_frequency_5min": 25, "error_rate_30min": 0.3},
        "risk_indicators": {"risk_score": 75, "requires_llm_analysis": True}
    }
    
    result = execute_rule_engine_scan(
        json.dumps(sample_packet), 
        json.dumps(sample_context)
    )
    print("规则引擎扫描测试结果:")
    print(result)