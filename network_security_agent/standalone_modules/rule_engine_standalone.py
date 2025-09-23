"""
网络安全检测智能体 - 独立规则引擎扫描模块
适用于工作流编排中的Python代码执行模块，无需外部依赖
"""
import json
import re
from datetime import datetime
from typing import Dict, Any, List, Tuple, Optional


def execute_rule_engine_scan(packet_data: str, context_features: str) -> str:
    """
    工作流编排调用的主函数 - 独立版本
    
    Args:
        packet_data: 报文输入模块的输出JSON数据
        context_features: 上下文特征提取模块的输出JSON数据
        
    Returns:
        str: JSON格式的扫描检测结果
    """
    
    # 内嵌的攻击签名和检测规则
    def get_attack_rules():
        """获取攻击检测规则"""
        return {
            'sql_injection': [
                {
                    'name': "SQL注入-联合查询",
                    'attack_type': "SQL注入",
                    'pattern': r"union\s+select|union\s+all\s+select",
                    'description': "检测到SQL联合查询注入尝试",
                    'risk_level': "高风险",
                    'confidence': 0.9
                },
                {
                    'name': "SQL注入-布尔盲注",
                    'attack_type': "SQL注入",
                    'pattern': r"(and|or)\s+\d+\s*=\s*\d+|'\s*(and|or)\s+'[^']*'\s*=\s*'[^']*'",
                    'description': "检测到SQL布尔盲注尝试",
                    'risk_level': "高风险",
                    'confidence': 0.8
                },
                {
                    'name': "SQL注入-注释绕过",
                    'attack_type': "SQL注入",
                    'pattern': r"--\s|#|\*/|/\*",
                    'description': "检测到SQL注释绕过尝试",
                    'risk_level': "中风险",
                    'confidence': 0.7
                },
                {
                    'name': "SQL注入-堆叠查询",
                    'attack_type': "SQL注入",
                    'pattern': r";\s*(drop|insert|delete|update|create|alter)\s+",
                    'description': "检测到SQL堆叠查询注入",
                    'risk_level': "严重",
                    'confidence': 0.95
                }
            ],
            'xss': [
                {
                    'name': "XSS-脚本标签",
                    'attack_type': "跨站脚本攻击",
                    'pattern': r"<script[^>]*>.*?</script>|<script[^>]*/>",
                    'description': "检测到XSS脚本标签注入",
                    'risk_level': "高风险",
                    'confidence': 0.85
                },
                {
                    'name': "XSS-事件处理器",
                    'attack_type': "跨站脚本攻击",
                    'pattern': r"on(load|error|click|mouseover|focus|blur)\s*=",
                    'description': "检测到XSS事件处理器注入",
                    'risk_level': "高风险",
                    'confidence': 0.8
                },
                {
                    'name': "XSS-JavaScript协议",
                    'attack_type': "跨站脚本攻击",
                    'pattern': r"javascript:|vbscript:|data:text/html",
                    'description': "检测到XSS伪协议注入",
                    'risk_level': "中风险",
                    'confidence': 0.75
                },
                {
                    'name': "XSS-编码绕过",
                    'attack_type': "跨站脚本攻击",
                    'pattern': r"&#x?[0-9a-f]+;|%[0-9a-f]{2}|\\x[0-9a-f]{2}",
                    'description': "检测到XSS编码绕过尝试",
                    'risk_level': "中风险",
                    'confidence': 0.7
                }
            ],
            'command_injection': [
                {
                    'name': "命令注入-系统命令",
                    'attack_type': "命令注入",
                    'pattern': r";\s*(cat|ls|pwd|id|whoami|uname|ps|netstat)\s|`(cat|ls|pwd|id|whoami)",
                    'description': "检测到系统命令注入尝试",
                    'risk_level': "高风险",
                    'confidence': 0.85
                },
                {
                    'name': "命令注入-管道符",
                    'attack_type': "命令注入",
                    'pattern': r"\|\s*(nc|curl|wget|python|perl|ruby|php)",
                    'description': "检测到管道符命令注入",
                    'risk_level': "高风险",
                    'confidence': 0.8
                },
                {
                    'name': "命令注入-反引号",
                    'attack_type': "命令注入",
                    'pattern': r"`[^`]*`|\$\([^)]*\)",
                    'description': "检测到反引号命令执行",
                    'risk_level': "中风险",
                    'confidence': 0.75
                }
            ],
            'directory_traversal': [
                {
                    'name': "目录遍历-相对路径",
                    'attack_type': "目录遍历",
                    'pattern': r"\.\./|\.\.\\\|%2e%2e%2f|%2e%2e%5c",
                    'description': "检测到目录遍历攻击",
                    'risk_level': "中风险",
                    'confidence': 0.8
                },
                {
                    'name': "目录遍历-敏感文件",
                    'attack_type': "目录遍历",
                    'pattern': r"/etc/passwd|/etc/shadow|win\.ini|boot\.ini",
                    'description': "检测到敏感文件访问尝试",
                    'risk_level': "高风险",
                    'confidence': 0.9
                }
            ],
            'scanner_probe': [
                {
                    'name': "扫描器探测-工具特征",
                    'attack_type': "扫描器探测",
                    'pattern': r"(sqlmap|nmap|masscan|nikto|dirb|gobuster|burpsuite|owasp zap|w3af|acunetix)",
                    'description': "检测到扫描器工具特征",
                    'risk_level': "中风险",
                    'confidence': 0.95
                }
            ]
        }
    
    def detect_attacks_by_rules(packet_dict: Dict, context_dict: Dict):
        """基于规则检测攻击"""
        matched_signatures = []
        attack_types = set()
        evidence = {}
        
        # 构建测试字符串
        test_strings = [
            packet_dict.get('url', ''),
            packet_dict.get('body', ''),
            packet_dict.get('user_agent', ''),
            ' '.join(packet_dict.get('query_params', {}).values()),
            ' '.join(packet_dict.get('post_params', {}).values()),
            ' '.join(packet_dict.get('headers', {}).values())
        ]
        
        # 获取所有检测规则
        attack_rules = get_attack_rules()
        
        # 检查所有规则类别
        for category, rules in attack_rules.items():
            for rule in rules:
                for i, test_string in enumerate(test_strings):
                    if test_string and re.search(rule['pattern'], test_string, re.IGNORECASE):
                        matched_signatures.append(rule)
                        attack_types.add(rule['attack_type'])
                        
                        if category not in evidence:
                            evidence[category] = []
                        
                        evidence[category].append({
                            'matched_pattern': rule['pattern'],
                            'matched_content': test_string[:200],
                            'rule_name': rule['name'],
                            'test_string_index': i
                        })
        
        return matched_signatures, list(attack_types), evidence
    
    def detect_xxe_attacks(packet_dict: Dict):
        """检测XXE攻击"""
        body = packet_dict.get('body', '')
        content_type = packet_dict.get('headers', {}).get('Content-Type', '')
        
        if 'xml' in content_type.lower() or body.strip().startswith('<?xml'):
            xxe_patterns = [
                r'<!ENTITY.*>',
                r'SYSTEM\s+["\']file://',
                r'SYSTEM\s+["\']http://',
                r'<!DOCTYPE.*\[.*<!ENTITY'
            ]
            
            for pattern in xxe_patterns:
                if re.search(pattern, body, re.IGNORECASE | re.DOTALL):
                    return {
                        'name': "XXE外部实体注入",
                        'attack_type': "XML外部实体注入",
                        'pattern': pattern,
                        'description': "检测到XXE外部实体注入尝试",
                        'risk_level': "高风险",
                        'confidence': 0.8
                    }
        return None
    
    def detect_ssrf_attacks(packet_dict: Dict):
        """检测SSRF攻击"""
        test_strings = [
            packet_dict.get('url', ''),
            packet_dict.get('body', ''),
            ' '.join(packet_dict.get('query_params', {}).values()),
            ' '.join(packet_dict.get('post_params', {}).values())
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
                    return {
                        'name': "SSRF服务端请求伪造",
                        'attack_type': "服务端请求伪造",
                        'pattern': pattern,
                        'description': "检测到SSRF攻击尝试",
                        'risk_level': "高风险",
                        'confidence': 0.75
                    }
        return None
    
    def detect_webshell_upload(packet_dict: Dict):
        """检测Web Shell上传"""
        body = packet_dict.get('body', '')
        content_type = packet_dict.get('headers', {}).get('Content-Type', '')
        
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
                    return {
                        'name': "Web Shell上传",
                        'attack_type': "Web Shell上传",
                        'pattern': pattern,
                        'description': "检测到Web Shell上传尝试",
                        'risk_level': "严重",
                        'confidence': 0.9
                    }
        return None
    
    def detect_brute_force_attacks(packet_dict: Dict, context_dict: Dict):
        """检测暴力破解攻击"""
        url = packet_dict.get('url', '').lower()
        method = packet_dict.get('method', '')
        
        # 检测登录相关的暴力破解
        if method == 'POST' and any(keyword in url for keyword in ['login', 'signin', 'auth', 'admin']):
            ip_features = context_dict.get('ip_features', {})
            time_features = context_dict.get('time_features', {})
            
            # 基于频率判断
            if (ip_features.get('request_frequency_5min', 0) > 30 and
                time_features.get('requests_last_1min', 0) > 10):
                
                return {
                    'name': "暴力破解攻击",
                    'attack_type': "暴力破解",
                    'pattern': "high_frequency_login",
                    'description': "检测到高频登录尝试，疑似暴力破解",
                    'risk_level': "高风险",
                    'confidence': 0.7
                }
        return None
    
    def detect_ddos_attacks(context_dict: Dict):
        """检测DDoS攻击"""
        time_features = context_dict.get('time_features', {})
        
        # 基于请求频率判断DDoS
        if (time_features.get('requests_last_1min', 0) > 100 or
            time_features.get('requests_last_5min', 0) > 300):
            
            return {
                'name': "DDoS攻击",
                'attack_type': "分布式拒绝服务攻击",
                'pattern': "high_frequency_requests",
                'description': "检测到异常高频请求，疑似DDoS攻击",
                'risk_level': "严重",
                'confidence': 0.6
            }
        return None
    
    def detect_frequency_anomalies(context_dict: Dict):
        """基于上下文特征检测频率异常"""
        risk_indicators = context_dict.get('risk_indicators', {})
        
        if risk_indicators.get('risk_score', 0) >= 60:
            return {
                'name': "频率异常检测",
                'attack_type': "可疑频次访问",
                'pattern': "context_analysis",
                'description': "基于上下文特征检测到异常行为模式",
                'risk_level': "中风险",
                'confidence': risk_indicators.get('risk_score', 0) / 100
            }
        return None
    
    def calculate_final_risk_level(matched_signatures: List):
        """计算最终风险等级"""
        if not matched_signatures:
            return "低风险", 0.1
        
        # 统计各风险等级的数量
        risk_levels = [sig['risk_level'] for sig in matched_signatures]
        critical_count = risk_levels.count('严重')
        high_count = risk_levels.count('高风险')
        medium_count = risk_levels.count('中风险')
        
        if critical_count > 0:
            return "严重", 0.95
        elif high_count > 0:
            return "高风险", 0.85
        elif medium_count > 1:
            return "高风险", 0.75
        elif medium_count > 0:
            return "中风险", 0.65
        else:
            return "低风险", 0.3
    
    def generate_recommendations(attack_types: List, risk_level: str):
        """生成防护建议"""
        recommendations = []
        
        for attack_type in set(attack_types):
            if "SQL注入" in attack_type:
                recommendations.extend([
                    "立即阻断该IP地址",
                    "检查应用程序的SQL查询参数化",
                    "启用WAF SQL注入防护规则",
                    "审计数据库访问日志"
                ])
            elif "跨站脚本攻击" in attack_type:
                recommendations.extend([
                    "阻断请求并记录日志",
                    "检查输入输出过滤机制",
                    "启用内容安全策略(CSP)",
                    "对用户输入进行HTML编码"
                ])
            elif "命令注入" in attack_type:
                recommendations.extend([
                    "立即阻断并告警",
                    "检查系统命令执行接口",
                    "限制应用程序权限",
                    "启用系统调用监控"
                ])
            elif "分布式拒绝服务攻击" in attack_type:
                recommendations.extend([
                    "启用流量清洗",
                    "实施IP限频策略",
                    "联系ISP进行上游过滤",
                    "扩展服务器资源"
                ])
            elif "暴力破解" in attack_type:
                recommendations.extend([
                    "临时锁定该IP",
                    "启用账户锁定机制",
                    "实施验证码验证",
                    "监控异常登录尝试"
                ])
        
        if not recommendations:
            recommendations = ["请求安全，继续监控"]
        
        # 去重并限制数量
        return list(set(recommendations))[:8]
    
    def requires_llm_analysis(risk_level: str, matched_signatures: List, context_dict: Dict) -> bool:
        """判断是否需要LLM深度分析"""
        # 高风险或严重风险需要LLM分析
        if risk_level in ['高风险', '严重']:
            return True
        
        # 上下文特征异常需要LLM分析
        if context_dict.get('risk_indicators', {}).get('requires_llm_analysis', False):
            return True
        
        # 多种攻击类型并发需要LLM分析
        attack_types = set([sig['attack_type'] for sig in matched_signatures])
        if len(attack_types) > 2:
            return True
        
        return False
    
    # 主处理逻辑
    try:
        scan_count = 1  # 简化处理
        
        packet_dict = json.loads(packet_data)
        context_dict = json.loads(context_features)
        
        # 执行各类攻击检测
        matched_signatures = []
        attack_types = []
        evidence = {}
        suspicious_features = []
        
        # 1. 基于规则的检测
        rule_signatures, rule_attack_types, rule_evidence = detect_attacks_by_rules(packet_dict, context_dict)
        matched_signatures.extend(rule_signatures)
        attack_types.extend(rule_attack_types)
        evidence.update(rule_evidence)
        
        # 2. 特殊攻击检测
        special_detections = [
            detect_xxe_attacks(packet_dict),
            detect_ssrf_attacks(packet_dict),
            detect_webshell_upload(packet_dict),
            detect_brute_force_attacks(packet_dict, context_dict),
            detect_ddos_attacks(context_dict),
            detect_frequency_anomalies(context_dict)
        ]
        
        for detection in special_detections:
            if detection:
                matched_signatures.append(detection)
                attack_types.append(detection['attack_type'])
        
        # 3. 行为异常检测
        anomaly_features = context_dict.get('anomaly_features', {})
        if anomaly_features.get('user_agent_anomalies'):
            suspicious_features.append("User-Agent异常")
        if anomaly_features.get('suspicious_encoding'):
            suspicious_features.append("可疑编码模式")
        if anomaly_features.get('unusual_header_count', 0) > 5:
            suspicious_features.append("异常HTTP头部")
        
        # 4. 计算最终风险等级和置信度
        is_attack = len(matched_signatures) > 0
        risk_level, confidence_score = calculate_final_risk_level(matched_signatures)
        
        # 5. 生成防护建议
        recommendations = generate_recommendations(attack_types, risk_level)
        
        # 6. 构建返回结果
        result = {
            'scan_id': f"SCAN_{scan_count}_{int(datetime.now().timestamp())}",
            'scan_timestamp': datetime.now().isoformat(),
            'packet_id': packet_dict.get('packet_id', ''),
            'is_attack': is_attack,
            'attack_types': list(set(attack_types)),
            'risk_level': risk_level,
            'confidence_score': confidence_score,
            'matched_signatures': [
                {
                    'name': sig['name'],
                    'attack_type': sig['attack_type'],
                    'description': sig['description'],
                    'confidence': sig['confidence']
                } for sig in matched_signatures
            ],
            'suspicious_features': suspicious_features,
            'evidence': evidence,
            'recommendations': recommendations,
            'requires_llm_analysis': requires_llm_analysis(risk_level, matched_signatures, context_dict)
        }
        
        return json.dumps(result, ensure_ascii=False, indent=2)
        
    except Exception as e:
        error_result = {
            'error': True,
            'error_message': str(e),
            'scan_id': f"ERR_SCAN_{scan_count}_{int(datetime.now().timestamp())}",
            'scan_timestamp': datetime.now().isoformat()
        }
        return json.dumps(error_result, ensure_ascii=False, indent=2)


# 测试代码
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
    print("独立规则引擎扫描测试结果:")
    print(result)