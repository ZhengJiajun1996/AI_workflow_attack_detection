"""
响应生成器模块 (BF)
功能：生成最终的安全响应报告
输入：decision_result (决策结果) 或 llm_result (LLM分析结果), original_decision (原始决策)
输出：完整的检测结果和建议
"""

def main(decision_result, llm_result=None, original_decision=None):
    import json
    from datetime import datetime
    
    try:
        # 解析输入
        decision_data = json.loads(decision_result)
        
        # 如果有LLM结果，使用LLM分析；否则使用原始决策
        if llm_result:
            try:
                llm_data = json.loads(llm_result)
                # 使用LLM分析结果
                detect_result = {
                    'message_index': 0,  # 将由循环变量更新模块设置
                    'timestamp': datetime.now().isoformat(),
                    'attack_flag': llm_data.get('attack_flag', decision_data.get('attack_flag', False)),
                    'attack_type': llm_data.get('attack_type', decision_data.get('attack_type', 'none')),
                    'risk_score': llm_data.get('risk_score', decision_data.get('risk_score', 0)),
                    'risk_assessment': llm_data.get('risk_assessment', decision_data.get('risk_assessment', '')),
                    'threat_level': llm_data.get('threat_level', 'medium'),
                    'detection_method': 'llm_enhanced',
                    'confidence': llm_data.get('confidence', 0.9),
                    'attack_vector': llm_data.get('attack_vector', ''),
                    'potential_impact': llm_data.get('potential_impact', ''),
                    'false_positive': llm_data.get('false_positive', False),
                    'analysis_reasoning': llm_data.get('analysis_reasoning', ''),
                    'recommendations': llm_data.get('recommendations', []),
                    'immediate_actions': llm_data.get('immediate_actions', []),
                    'technical_details': {
                        'original_risk_score': decision_data.get('risk_score', 0),
                        'llm_adjusted_score': llm_data.get('risk_score', 0),
                        'score_adjustment': llm_data.get('risk_score', 0) - decision_data.get('risk_score', 0),
                        'detection_confidence': llm_data.get('confidence', 0.9)
                    }
                }
            except:
                # LLM解析失败，使用原始决策结果
                detect_result = _generate_fallback_response(decision_data, 'llm_parse_error')
        else:
            # 使用原始决策结果生成响应
            detect_result = _generate_rule_engine_response(decision_data)
        
        return {
            'output': json.dumps(detect_result)
        }
    except Exception as e:
        return {
            'output': json.dumps({
                'error': True,
                'message': str(e)
            })
        }

def _generate_rule_engine_response(decision_data):
    """生成基于规则引擎的响应"""
    from datetime import datetime
    
    risk_score = decision_data.get('risk_score', 0)
    attack_flag = decision_data.get('attack_flag', False)
    attack_type = decision_data.get('attack_type', 'none')
    
    # 生成响应结果
    detect_result = {
        'message_index': 0,  # 将由循环变量更新模块设置
        'timestamp': datetime.now().isoformat(),
        'attack_flag': attack_flag,
        'attack_type': attack_type,
        'risk_score': risk_score,
        'risk_assessment': decision_data.get('risk_assessment', ''),
        'threat_level': _get_threat_level(risk_score),
        'detection_method': 'rule_engine',
        'confidence': _calculate_confidence(risk_score, attack_flag),
        'attack_vector': _get_attack_vector_description(attack_type),
        'potential_impact': _get_potential_impact(attack_type, risk_score),
        'false_positive': False,
        'analysis_reasoning': f'基于规则引擎检测，识别到{attack_type}攻击模式',
        'recommendations': _generate_recommendations(attack_flag, attack_type, risk_score),
        'immediate_actions': _generate_immediate_actions(attack_flag, risk_score),
        'technical_details': {
            'detected_attacks': decision_data.get('detected_attacks', []),
            'attack_details': decision_data.get('attack_details', {}),
            'risk_factors': decision_data.get('risk_factors', []),
            'confidence': decision_data.get('confidence', 0.0)
        }
    }
    
    return detect_result

def _generate_fallback_response(decision_data, error_type):
    """生成回退响应"""
    from datetime import datetime
    
    detect_result = {
        'message_index': 0,
        'timestamp': datetime.now().isoformat(),
        'attack_flag': decision_data.get('attack_flag', False),
        'attack_type': decision_data.get('attack_type', 'none'),
        'risk_score': decision_data.get('risk_score', 0),
        'risk_assessment': decision_data.get('risk_assessment', ''),
        'threat_level': _get_threat_level(decision_data.get('risk_score', 0)),
        'detection_method': 'rule_engine_fallback',
        'confidence': 0.6,
        'attack_vector': _get_attack_vector_description(decision_data.get('attack_type', 'none')),
        'potential_impact': _get_potential_impact(decision_data.get('attack_type', 'none'), decision_data.get('risk_score', 0)),
        'false_positive': False,
        'analysis_reasoning': f'LLM分析失败({error_type})，使用规则引擎结果',
        'recommendations': _generate_recommendations(decision_data.get('attack_flag', False), decision_data.get('attack_type', 'none'), decision_data.get('risk_score', 0)),
        'immediate_actions': ['继续监控', '记录日志'],
        'technical_details': {
            'error_type': error_type,
            'fallback_used': True
        }
    }
    
    return detect_result

def _get_threat_level(risk_score):
    """根据风险评分确定威胁等级"""
    if risk_score >= 90:
        return 'critical'
    elif risk_score >= 70:
        return 'high'
    elif risk_score >= 50:
        return 'medium'
    elif risk_score >= 30:
        return 'low'
    else:
        return 'minimal'

def _calculate_confidence(risk_score, attack_flag):
    """计算置信度"""
    if attack_flag:
        if risk_score >= 80:
            return 0.9
        elif risk_score >= 60:
            return 0.8
        elif risk_score >= 40:
            return 0.7
        else:
            return 0.6
    else:
        return 0.8

def _get_attack_vector_description(attack_type):
    """获取攻击向量描述"""
    descriptions = {
        'sql_injection': '通过SQL查询注入恶意代码，试图访问或修改数据库',
        'xss': '通过跨站脚本攻击，试图在用户浏览器中执行恶意代码',
        'command_injection': '通过系统命令注入，试图在服务器上执行恶意命令',
        'path_traversal': '通过目录遍历攻击，试图访问系统敏感文件',
        'ldap_injection': '通过LDAP查询注入，试图访问目录服务',
        'xml_injection': '通过XML注入，试图破坏XML解析或访问敏感数据',
        'nosql_injection': '通过NoSQL查询注入，试图绕过认证或访问数据',
        'xxe_injection': '通过XML外部实体注入，试图读取敏感文件或进行SSRF',
        'ssrf': '通过服务器端请求伪造，试图访问内部服务或进行端口扫描',
        'csrf': '通过跨站请求伪造，试图以用户身份执行未授权操作',
        'file_upload': '通过恶意文件上传，试图在服务器上执行恶意代码',
        'multiple': '检测到多种攻击类型，可能存在复合攻击',
        'none': '未检测到明显的攻击模式'
    }
    return descriptions.get(attack_type, f'未知攻击类型: {attack_type}')

def _get_potential_impact(attack_type, risk_score):
    """获取潜在影响描述"""
    impacts = {
        'sql_injection': '可能导致数据泄露、数据篡改、权限提升或数据库完全控制',
        'xss': '可能导致会话劫持、敏感信息窃取、恶意重定向或恶意软件传播',
        'command_injection': '可能导致服务器完全控制、数据泄露、系统破坏或横向移动',
        'path_traversal': '可能导致敏感文件泄露、配置信息暴露或系统指纹识别',
        'ldap_injection': '可能导致目录服务信息泄露、认证绕过或权限提升',
        'xml_injection': '可能导致XML解析器崩溃、敏感数据泄露或DoS攻击',
        'nosql_injection': '可能导致数据泄露、认证绕过或数据篡改',
        'xxe_injection': '可能导致敏感文件读取、SSRF攻击或DoS攻击',
        'ssrf': '可能导致内部服务访问、端口扫描、内网渗透或敏感信息泄露',
        'csrf': '可能导致未授权操作、数据篡改或用户账户劫持',
        'file_upload': '可能导致服务器控制、恶意软件传播或数据泄露',
        'multiple': '复合攻击可能导致多重影响，包括数据泄露、系统控制和横向移动',
        'none': '无明显安全影响'
    }
    
    base_impact = impacts.get(attack_type, '未知攻击影响')
    
    # 根据风险评分调整影响描述
    if risk_score >= 80:
        severity = '严重'
    elif risk_score >= 60:
        severity = '高'
    elif risk_score >= 40:
        severity = '中等'
    else:
        severity = '低'
    
    return f'{severity}风险: {base_impact}'

def _generate_recommendations(attack_flag, attack_type, risk_score):
    """生成防护建议"""
    recommendations = []
    
    if attack_flag:
        # 通用攻击防护建议
        recommendations.extend([
            '立即阻断此请求',
            '记录攻击日志并告警',
            '分析攻击来源IP',
            '检查系统日志是否有其他类似攻击'
        ])
        
        # 针对特定攻击类型的建议
        if attack_type == 'sql_injection':
            recommendations.extend([
                '使用参数化查询或预编译语句',
                '实施输入验证和过滤',
                '启用数据库访问日志监控',
                '考虑使用Web应用防火墙(WAF)'
            ])
        elif attack_type == 'xss':
            recommendations.extend([
                '实施输出编码和过滤',
                '设置CSP(内容安全策略)',
                '启用XSS防护头',
                '对用户输入进行严格验证'
            ])
        elif attack_type == 'command_injection':
            recommendations.extend([
                '避免直接执行用户输入',
                '使用安全的API替代系统命令',
                '实施严格的输入验证',
                '限制系统命令执行权限'
            ])
        elif attack_type == 'path_traversal':
            recommendations.extend([
                '验证和规范化文件路径',
                '限制文件访问权限',
                '使用白名单验证文件访问',
                '实施目录访问控制'
            ])
        elif attack_type == 'ssrf':
            recommendations.extend([
                '验证和过滤外部URL',
                '使用内网IP黑名单',
                '限制网络访问权限',
                '实施请求目标验证'
            ])
        
        # 根据风险评分添加建议
        if risk_score >= 80:
            recommendations.extend([
                '启动应急响应程序',
                '通知安全团队',
                '考虑临时阻断来源IP',
                '进行深度安全分析'
            ])
        elif risk_score >= 60:
            recommendations.extend([
                '加强监控',
                '分析攻击模式',
                '更新安全规则'
            ])
    else:
        # 正常请求的建议
        if risk_score >= 30:
            recommendations.extend([
                '继续监控此来源',
                '记录请求日志',
                '分析请求模式'
            ])
        else:
            recommendations.extend([
                '正常处理',
                '定期安全审计'
            ])
    
    return recommendations

def _generate_immediate_actions(attack_flag, risk_score):
    """生成立即执行的操作"""
    actions = []
    
    if attack_flag:
        if risk_score >= 80:
            actions.extend([
                '立即阻断请求',
                '记录攻击日志',
                '发送紧急告警',
                '启动应急响应'
            ])
        elif risk_score >= 60:
            actions.extend([
                '记录攻击日志',
                '发送告警通知',
                '加强监控',
                '分析攻击来源'
            ])
        else:
            actions.extend([
                '记录日志',
                '继续监控',
                '分析模式'
            ])
    else:
        actions.append('正常处理')
    
    return actions