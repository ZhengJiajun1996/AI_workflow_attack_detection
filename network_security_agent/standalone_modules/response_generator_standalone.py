"""
网络安全检测智能体 - 独立响应生成器模块
适用于工作流编排中的Python代码执行模块，无需外部依赖
"""
import json
from datetime import datetime
from typing import Dict, Any, List


def generate_security_response(llm_analysis: str, packet_data: str, 
                              context_data: str, rule_result: str) -> str:
    """
    工作流编排调用的主函数 - 独立版本
    生成最终的安全响应报告
    
    Args:
        llm_analysis: LLM分析结果JSON数据
        packet_data: 报文数据JSON
        context_data: 上下文特征JSON
        rule_result: 规则引擎结果JSON
        
    Returns:
        str: JSON格式的安全响应报告
    """
    
    def determine_final_threat_level(rule_dict: Dict, llm_content: str) -> str:
        """确定最终威胁等级"""
        rule_level = rule_dict.get('risk_level', '低风险')
        
        # 如果LLM分析提到更高的威胁等级，则采用更高的等级
        if isinstance(llm_content, str):
            llm_lower = llm_content.lower()
            if any(keyword in llm_lower for keyword in ['严重威胁', 'critical', '紧急']):
                return '严重威胁'
            elif any(keyword in llm_lower for keyword in ['高风险', 'high risk', '危险']):
                return '高风险' if rule_level != '严重' else rule_level
            elif any(keyword in llm_lower for keyword in ['中风险', 'medium risk', '可疑']):
                return '中风险' if rule_level in ['低风险'] else rule_level
        
        return rule_level
    
    def determine_response_action(threat_level: str, rule_dict: Dict) -> Dict[str, Any]:
        """确定响应动作"""
        if threat_level == '严重威胁':
            return {
                'action': 'block_immediately',
                'description': '立即阻断IP地址和请求',
                'priority': 'critical',
                'auto_execute': True,
                'notification_required': True,
                'escalation_required': True
            }
        elif threat_level == '高风险':
            return {
                'action': 'block_and_alert',
                'description': '阻断请求并生成高优先级告警',
                'priority': 'high',
                'auto_execute': True,
                'notification_required': True,
                'escalation_required': False
            }
        elif threat_level == '中风险':
            return {
                'action': 'alert_and_monitor',
                'description': '生成告警并加强监控',
                'priority': 'medium',
                'auto_execute': False,
                'notification_required': True,
                'escalation_required': False
            }
        else:
            return {
                'action': 'allow_and_log',
                'description': '允许请求通过并记录日志',
                'priority': 'low',
                'auto_execute': True,
                'notification_required': False,
                'escalation_required': False
            }
    
    def generate_executive_summary(packet_dict: Dict, rule_dict: Dict, threat_level: str) -> str:
        """生成执行摘要"""
        if not rule_dict.get('is_attack', False):
            return f"检测到来自 {packet_dict.get('source_ip', 'unknown')} 的正常HTTP请求，未发现威胁。"
        
        attack_types = rule_dict.get('attack_types', [])
        confidence = rule_dict.get('confidence_score', 0.0)
        
        if len(attack_types) == 1:
            attack_desc = attack_types[0]
        elif len(attack_types) > 1:
            attack_desc = f"多种攻击类型（{', '.join(attack_types[:3])}等）"
        else:
            attack_desc = "未知攻击类型"
        
        return (f"检测到来自 {packet_dict.get('source_ip', 'unknown')} 的{attack_desc}攻击，"
                f"威胁等级：{threat_level}，检测置信度：{confidence:.1%}。"
                f"目标URL：{packet_dict.get('url', 'unknown')[:50]}...")
    
    def generate_technical_details(packet_dict: Dict, context_dict: Dict, 
                                   rule_dict: Dict, llm_content: str) -> Dict[str, Any]:
        """生成技术详情"""
        return {
            'attack_vectors': {
                'primary_vector': rule_dict.get('attack_types', ['unknown'])[0] if rule_dict.get('attack_types') else 'unknown',
                'attack_signatures': [sig['name'] for sig in rule_dict.get('matched_signatures', [])],
                'payload_analysis': rule_dict.get('evidence', {})
            },
            'network_context': {
                'source_ip': packet_dict.get('source_ip', ''),
                'request_frequency': context_dict.get('ip_features', {}).get('request_frequency_5min', 0),
                'unique_urls': context_dict.get('ip_features', {}).get('unique_urls_accessed', 0),
                'error_rate': context_dict.get('ip_features', {}).get('error_rate_30min', 0)
            },
            'request_details': {
                'method': packet_dict.get('method', ''),
                'url': packet_dict.get('url', ''),
                'user_agent': packet_dict.get('user_agent', ''),
                'content_length': len(packet_dict.get('body', '')),
                'suspicious_patterns': packet_dict.get('suspicious_patterns', {})
            },
            'behavioral_analysis': {
                'anomaly_features': context_dict.get('anomaly_features', {}),
                'risk_factors': context_dict.get('risk_indicators', {}).get('risk_factors', []),
                'session_analysis': context_dict.get('session_features', {})
            }
        }
    
    def generate_protection_recommendations(rule_dict: Dict, threat_level: str) -> Dict[str, List[str]]:
        """生成防护建议"""
        immediate_actions = []
        short_term_actions = []
        long_term_actions = []
        
        if threat_level in ['严重威胁', '高风险']:
            immediate_actions.extend([
                '立即阻断源IP地址',
                '隔离受影响的服务器或服务',
                '启动安全事件响应流程',
                '通知安全运营中心(SOC)'
            ])
            
            short_term_actions.extend([
                '分析攻击者的其他可能活动',
                '检查相关日志和系统状态',
                '更新防火墙和IPS规则',
                '进行漏洞扫描和安全评估'
            ])
            
            long_term_actions.extend([
                '修复相关安全漏洞',
                '加强应用安全防护',
                '实施更严格的访问控制',
                '提升安全监控能力'
            ])
        
        elif threat_level == '中风险':
            immediate_actions.extend([
                '加强对该IP的监控',
                '记录详细的访问日志',
                '考虑实施访问限制'
            ])
            
            short_term_actions.extend([
                '分析访问模式和行为',
                '检查应用程序安全配置',
                '更新安全规则和策略'
            ])
            
            long_term_actions.extend([
                '优化安全检测规则',
                '加强用户行为分析',
                '定期进行安全培训'
            ])
        
        # 基于具体攻击类型添加针对性建议
        for attack_type in rule_dict.get('attack_types', []):
            if 'SQL注入' in attack_type:
                immediate_actions.append('检查数据库连接和查询日志')
                short_term_actions.append('审计所有SQL查询参数化')
                long_term_actions.append('实施数据库活动监控')
            
            elif '跨站脚本攻击' in attack_type:
                immediate_actions.append('检查输出过滤和编码')
                short_term_actions.append('启用内容安全策略(CSP)')
                long_term_actions.append('实施输入验证框架')
            
            elif '分布式拒绝服务攻击' in attack_type:
                immediate_actions.append('启用流量清洗服务')
                short_term_actions.append('调整负载均衡配置')
                long_term_actions.append('部署DDoS防护解决方案')
        
        return {
            'immediate': list(set(immediate_actions))[:8],
            'short_term': list(set(short_term_actions))[:6],
            'long_term': list(set(long_term_actions))[:6]
        }
    
    def generate_follow_up_actions(threat_level: str, rule_dict: Dict) -> List[Dict[str, Any]]:
        """生成后续跟踪动作"""
        actions = []
        
        if threat_level in ['严重威胁', '高风险']:
            actions.extend([
                {
                    'action': 'incident_investigation',
                    'description': '启动安全事件调查',
                    'timeline': '立即',
                    'responsible': 'security_team'
                },
                {
                    'action': 'threat_intelligence_update',
                    'description': '更新威胁情报库',
                    'timeline': '24小时内',
                    'responsible': 'threat_intel_team'
                },
                {
                    'action': 'vulnerability_assessment',
                    'description': '进行相关漏洞评估',
                    'timeline': '72小时内',
                    'responsible': 'security_team'
                }
            ])
        
        if rule_dict.get('is_attack', False):
            actions.append({
                'action': 'pattern_analysis',
                'description': '分析攻击模式和趋势',
                'timeline': '7天内',
                'responsible': 'analyst_team'
            })
        
        return actions
    
    def calculate_processing_time(packet_dict: Dict) -> float:
        """计算处理时间（毫秒）"""
        try:
            if 'timestamp' in packet_dict:
                packet_time = datetime.fromisoformat(packet_dict['timestamp'].replace('Z', '+00:00'))
                current_time = datetime.now()
                # 简化时区处理
                if packet_time.tzinfo is not None and current_time.tzinfo is None:
                    current_time = current_time.replace(tzinfo=packet_time.tzinfo)
                return abs((current_time - packet_time).total_seconds() * 1000)
            else:
                return 0.0
        except:
            return 0.0
    
    # 主处理逻辑
    try:
        response_count = 1  # 简化处理
        
        # 解析输入数据
        try:
            llm_dict = json.loads(llm_analysis) if isinstance(llm_analysis, str) else llm_analysis
        except:
            llm_dict = {'content': str(llm_analysis)}
        
        packet_dict = json.loads(packet_data)
        context_dict = json.loads(context_data)
        rule_dict = json.loads(rule_result)
        
        # 解析LLM分析结果
        llm_content = llm_dict.get('content', '') if isinstance(llm_dict, dict) else str(llm_dict)
        
        # 确定最终的威胁等级
        final_threat_level = determine_final_threat_level(rule_dict, llm_content)
        
        # 确定响应动作
        response_action = determine_response_action(final_threat_level, rule_dict)
        
        # 生成执行摘要
        executive_summary = generate_executive_summary(packet_dict, rule_dict, final_threat_level)
        
        # 生成技术详情
        technical_details = generate_technical_details(packet_dict, context_dict, rule_dict, llm_content)
        
        # 生成防护建议
        protection_recommendations = generate_protection_recommendations(rule_dict, final_threat_level)
        
        # 构建完整响应
        response = {
            'response_id': f"RESP_{response_count}_{int(datetime.now().timestamp())}",
            'timestamp': datetime.now().isoformat(),
            'packet_id': packet_dict.get('packet_id', ''),
            'source_ip': packet_dict.get('source_ip', ''),
            
            # 威胁评估结果
            'threat_assessment': {
                'is_malicious': rule_dict.get('is_attack', False),
                'threat_level': final_threat_level,
                'confidence_score': rule_dict.get('confidence_score', 0.0),
                'attack_types': rule_dict.get('attack_types', []),
                'risk_score': context_dict.get('risk_indicators', {}).get('risk_score', 0)
            },
            
            # 响应动作
            'response_action': response_action,
            
            # 执行摘要
            'executive_summary': executive_summary,
            
            # 技术详情
            'technical_details': technical_details,
            
            # LLM深度分析
            'llm_analysis': {
                'analysis_content': llm_content,
                'analysis_timestamp': datetime.now().isoformat()
            },
            
            # 防护建议
            'protection_recommendations': protection_recommendations,
            
            # 后续跟踪
            'follow_up_actions': generate_follow_up_actions(final_threat_level, rule_dict),
            
            # 相关指标
            'metrics': {
                'processing_time_ms': calculate_processing_time(packet_dict),
                'detection_rules_triggered': len(rule_dict.get('matched_signatures', [])),
                'context_risk_factors': len(context_dict.get('risk_indicators', {}).get('risk_factors', []))
            }
        }
        
        return json.dumps(response, ensure_ascii=False, indent=2)
        
    except Exception as e:
        error_result = {
            'error': True,
            'error_message': str(e),
            'response_id': f"ERR_RESP_{response_count}_{int(datetime.now().timestamp())}",
            'timestamp': datetime.now().isoformat()
        }
        return json.dumps(error_result, ensure_ascii=False, indent=2)


# 测试代码
if __name__ == "__main__":
    # 测试用例
    sample_llm_analysis = {
        'content': '检测到明确的SQL注入攻击，威胁等级为高风险。攻击者使用联合查询尝试获取数据库信息。'
    }
    
    sample_packet = {
        "packet_id": "PKT_1_1705392600",
        "timestamp": "2024-01-15T10:30:00",
        "source_ip": "192.168.1.100",
        "url": "/admin/login.php?id=1' UNION SELECT user,pass FROM admin--",
        "method": "POST",
        "user_agent": "sqlmap/1.6.12",
        "body": "username=admin&password=' OR '1'='1-- "
    }
    
    sample_context = {
        "ip_features": {"request_frequency_5min": 25, "error_rate_30min": 0.3},
        "risk_indicators": {"risk_score": 85, "risk_factors": ["high_frequency_requests"]}
    }
    
    sample_rule_result = {
        "is_attack": True,
        "attack_types": ["SQL注入"],
        "risk_level": "高风险",
        "confidence_score": 0.9,
        "matched_signatures": [{"name": "SQL注入-联合查询"}]
    }
    
    result = generate_security_response(
        json.dumps(sample_llm_analysis),
        json.dumps(sample_packet),
        json.dumps(sample_context),
        json.dumps(sample_rule_result)
    )
    
    print("独立安全响应生成器测试结果:")
    print(result)