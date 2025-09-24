"""
网络攻击检测智能体 - 最终响应生成模块
整合所有分析结果，生成最终的安全响应报告，标准main()函数格式
"""
import json
from datetime import datetime
from typing import Dict, Any


def main(packet_result, llm_analysis_result):
    """
    最终响应生成主函数
    
    Args:
        packet_result: 报文处理结果（文本格式）
        llm_analysis_result: LLM分析结果（文本格式）
        
    Returns:
        dict: 包含最终的安全响应报告
    """
    
    def determine_final_threat_level(packet_info, llm_analysis):
        """确定最终威胁等级"""
        # 从规则引擎获取初始等级
        rule_level = packet_info.get('risk_assessment', {}).get('risk_level', 'low')
        
        # 如果有LLM分析结果，考虑其建议
        if llm_analysis and isinstance(llm_analysis, str):
            llm_lower = llm_analysis.lower()
            if any(keyword in llm_lower for keyword in ['严重威胁', 'critical threat', '立即阻断']):
                return 'critical'
            elif any(keyword in llm_lower for keyword in ['高风险', 'high risk', '高危']):
                return 'high' if rule_level != 'critical' else rule_level
            elif any(keyword in llm_lower for keyword in ['中风险', 'medium risk', '可疑']):
                return 'medium' if rule_level in ['low'] else rule_level
            elif any(keyword in llm_lower for keyword in ['误报', 'false positive', '正常']):
                return 'low'  # LLM判断为误报
        
        return rule_level
    
    def determine_response_action(threat_level, attack_types):
        """确定响应动作"""
        actions = {
            'critical': {
                'action': 'block_immediately',
                'description': '立即阻断IP地址和所有相关请求',
                'priority': 'critical',
                'auto_execute': True,
                'notification_required': True,
                'escalation_required': True
            },
            'high': {
                'action': 'block_and_alert',
                'description': '阻断请求并生成高优先级告警',
                'priority': 'high',
                'auto_execute': True,
                'notification_required': True,
                'escalation_required': False
            },
            'medium': {
                'action': 'alert_and_monitor',
                'description': '生成告警并加强监控',
                'priority': 'medium',
                'auto_execute': False,
                'notification_required': True,
                'escalation_required': False
            },
            'low': {
                'action': 'log_and_continue',
                'description': '记录日志并继续监控',
                'priority': 'low',
                'auto_execute': True,
                'notification_required': False,
                'escalation_required': False
            }
        }
        
        return actions.get(threat_level, actions['low'])
    
    def generate_executive_summary(packet_info, threat_level, llm_analysis):
        """生成执行摘要"""
        source_ip = packet_info.get('source_ip', 'unknown')
        attack_types = [attack['type'] for attack in packet_info.get('detected_attacks', [])]
        
        if not packet_info.get('is_attack', False):
            return f"来自 {source_ip} 的请求经过分析确认为正常流量，无安全威胁。"
        
        # 构建攻击描述
        if len(attack_types) == 1:
            attack_desc = attack_types[0].replace('_', ' ').title()
        elif len(attack_types) > 1:
            attack_desc = f"多种攻击类型（{', '.join(attack_types[:2])}等）"
        else:
            attack_desc = "可疑活动"
        
        # 基础摘要
        summary = f"检测到来自 {source_ip} 的{attack_desc}，威胁等级：{threat_level.upper()}"
        
        # 添加上下文信息
        context_stats = packet_info.get('context_stats', {})
        if context_stats.get('request_frequency_5min', 0) > 10:
            summary += f"，该IP在5分钟内发起了 {context_stats['request_frequency_5min']:.1f} 次请求"
        
        # 如果有LLM分析，添加关键洞察
        if llm_analysis and isinstance(llm_analysis, str):
            if '自动化工具' in llm_analysis:
                summary += "，疑似使用自动化攻击工具"
            if '持续攻击' in llm_analysis or '系列攻击' in llm_analysis:
                summary += "，可能是持续性攻击活动的一部分"
        
        return summary + "。"
    
    def generate_protection_recommendations(threat_level, attack_types, llm_analysis):
        """生成防护建议"""
        recommendations = {
            'immediate': [],
            'short_term': [],
            'long_term': []
        }
        
        # 基于威胁等级的通用建议
        if threat_level in ['critical', 'high']:
            recommendations['immediate'].extend([
                '立即将源IP加入黑名单',
                '检查同一IP的其他活动',
                '通知安全运营团队',
                '启动事件响应流程'
            ])
            
            recommendations['short_term'].extend([
                '分析攻击模式和来源',
                '更新安全规则和策略',
                '加强相关系统监控'
            ])
            
        elif threat_level == 'medium':
            recommendations['immediate'].extend([
                '加强对该IP的监控',
                '记录详细访问日志'
            ])
            
            recommendations['short_term'].extend([
                '分析访问模式',
                '评估现有安全控制'
            ])
        
        # 基于攻击类型的专项建议
        for attack_type in attack_types:
            if attack_type == 'sql_injection':
                recommendations['immediate'].append('检查数据库访问日志')
                recommendations['short_term'].append('审核SQL查询参数化')
                recommendations['long_term'].append('部署数据库防火墙')
                
            elif attack_type == 'xss':
                recommendations['immediate'].append('检查输出编码机制')
                recommendations['short_term'].append('启用内容安全策略(CSP)')
                recommendations['long_term'].append('实施输入验证框架')
                
            elif attack_type == 'command_injection':
                recommendations['immediate'].append('检查系统命令执行接口')
                recommendations['short_term'].append('限制应用程序权限')
                recommendations['long_term'].append('部署应用程序沙箱')
        
        # 从LLM分析中提取额外建议
        if llm_analysis and isinstance(llm_analysis, str):
            if '补丁' in llm_analysis or 'patch' in llm_analysis.lower():
                recommendations['short_term'].append('检查并安装安全补丁')
            if '培训' in llm_analysis or 'training' in llm_analysis.lower():
                recommendations['long_term'].append('加强安全意识培训')
        
        # 通用长期建议
        recommendations['long_term'].extend([
            '定期进行安全评估',
            '持续优化检测规则',
            '建立威胁情报共享机制'
        ])
        
        # 去重并限制数量
        for category in recommendations:
            recommendations[category] = list(set(recommendations[category]))[:5]
        
        return recommendations
    
    def extract_llm_insights(llm_analysis):
        """从LLM分析中提取关键洞察"""
        insights = {
            'threat_confirmation': None,
            'attack_sophistication': None,
            'false_positive_probability': None,
            'key_findings': []
        }
        
        if not llm_analysis or not isinstance(llm_analysis, str):
            return insights
        
        # 提取威胁确认
        if any(keyword in llm_analysis.lower() for keyword in ['确认威胁', 'confirmed threat']):
            insights['threat_confirmation'] = 'confirmed'
        elif any(keyword in llm_analysis.lower() for keyword in ['误报', 'false positive']):
            insights['threat_confirmation'] = 'false_positive'
        
        # 提取攻击复杂度
        if any(keyword in llm_analysis.lower() for keyword in ['高级', 'sophisticated', '专业']):
            insights['attack_sophistication'] = 'high'
        elif any(keyword in llm_analysis.lower() for keyword in ['简单', 'basic', '初级']):
            insights['attack_sophistication'] = 'low'
        
        # 提取误报概率
        import re
        prob_match = re.search(r'误报概率[：:]\s*(\d+)%', llm_analysis)
        if prob_match:
            insights['false_positive_probability'] = int(prob_match.group(1))
        
        # 提取关键发现
        if '自动化工具' in llm_analysis:
            insights['key_findings'].append('使用自动化攻击工具')
        if '持续攻击' in llm_analysis:
            insights['key_findings'].append('疑似持续性攻击')
        if '内部威胁' in llm_analysis:
            insights['key_findings'].append('可能的内部威胁')
        
        return insights
    
    # 主处理逻辑
    try:
        # 解析输入数据
        packet_result_data = json.loads(packet_result)
        
        # 处理LLM分析结果
        llm_analysis_data = None
        llm_analysis_text = ""
        
        try:
            if llm_analysis_result and llm_analysis_result.strip():
                llm_analysis_data = json.loads(llm_analysis_result)
                
                # 检查是否跳过了LLM分析
                if llm_analysis_data.get('skip_llm_analysis'):
                    llm_analysis_text = "风险等级较低，跳过LLM深度分析"
                else:
                    # 假设LLM返回的是文本分析结果
                    llm_analysis_text = llm_analysis_data.get('analysis_result', 
                                                           llm_analysis_data.get('content', ''))
        except:
            # 如果解析失败，直接作为文本处理
            llm_analysis_text = llm_analysis_result
        
        # 提取关键信息
        processed_packet = packet_result_data.get('processed_packet', {})
        updated_context = packet_result_data.get('updated_context', {})
        
        # 确定最终威胁等级
        final_threat_level = determine_final_threat_level(processed_packet, llm_analysis_text)
        
        # 提取攻击类型
        attack_types = [attack['type'] for attack in processed_packet.get('detected_attacks', [])]
        
        # 确定响应动作
        response_action = determine_response_action(final_threat_level, attack_types)
        
        # 生成执行摘要
        executive_summary = generate_executive_summary(processed_packet, final_threat_level, llm_analysis_text)
        
        # 生成防护建议
        protection_recommendations = generate_protection_recommendations(
            final_threat_level, attack_types, llm_analysis_text
        )
        
        # 提取LLM洞察
        llm_insights = extract_llm_insights(llm_analysis_text)
        
        # 构建最终响应报告
        response_report = {
            'response_id': f"RESP_{int(datetime.now().timestamp())}",
            'timestamp': datetime.now().isoformat(),
            'packet_id': processed_packet.get('packet_id', ''),
            
            # 威胁评估
            'threat_assessment': {
                'final_threat_level': final_threat_level,
                'is_attack': processed_packet.get('is_attack', False),
                'attack_types': attack_types,
                'confidence_score': max([attack.get('confidence', 0) for attack in processed_packet.get('detected_attacks', [])], default=0),
                'risk_score': processed_packet.get('risk_assessment', {}).get('risk_score', 0)
            },
            
            # 响应动作
            'response_action': response_action,
            
            # 摘要和分析
            'executive_summary': executive_summary,
            'llm_insights': llm_insights,
            
            # 技术详情
            'technical_details': {
                'source_ip': processed_packet.get('source_ip', ''),
                'target_url': processed_packet.get('url', ''),
                'attack_patterns': processed_packet.get('detected_attacks', []),
                'context_statistics': processed_packet.get('context_stats', {}),
                'global_statistics': updated_context.get('global_stats', {})
            },
            
            # 防护建议
            'protection_recommendations': protection_recommendations,
            
            # 分析元数据
            'analysis_metadata': {
                'had_llm_analysis': bool(llm_analysis_text and llm_analysis_text != "风险等级较低，跳过LLM深度分析"),
                'processing_timestamp': datetime.now().isoformat(),
                'total_packets_analyzed': updated_context.get('global_stats', {}).get('total_packets', 0),
                'total_attacks_detected': updated_context.get('global_stats', {}).get('attack_packets', 0)
            }
        }
        
        return {
            'output': json.dumps(response_report)
        }
        
    except Exception as e:
        return {
            'output': json.dumps({
                'error': True,
                'message': f"响应生成失败: {str(e)}",
                'timestamp': datetime.now().isoformat()
            })
        }


# 测试代码
if __name__ == "__main__":
    # 测试用例
    test_packet_result = json.dumps({
        'processed_packet': {
            'packet_id': 'PKT_1_1234567890',
            'source_ip': '192.168.1.100',
            'url': '/admin/login.php?id=1\' UNION SELECT * FROM users--',
            'is_attack': True,
            'detected_attacks': [
                {
                    'type': 'sql_injection',
                    'confidence': 0.9
                }
            ],
            'risk_assessment': {
                'risk_score': 85,
                'risk_level': 'high'
            },
            'context_stats': {
                'request_frequency_5min': 25.3,
                'total_requests': 76
            }
        },
        'updated_context': {
            'global_stats': {
                'total_packets': 150,
                'attack_packets': 23
            }
        }
    })
    
    test_llm_result = json.dumps({
        'analysis_result': '经过深度分析，确认这是一次严重的SQL注入攻击，使用了自动化工具，建议立即阻断。误报概率：5%'
    })
    
    result = main(test_packet_result, test_llm_result)
    print("响应生成模块测试结果:")
    print(json.dumps(json.loads(result['output']), ensure_ascii=False, indent=2))