"""
网络攻击检测智能体 - LLM深度分析模块
用于需要深度分析的高风险报文，标准main()函数格式
"""
import json
from datetime import datetime
from typing import Dict, Any


def main(packet_result, context_data):
    """
    LLM深度分析的数据准备主函数
    
    Args:
        packet_result: 报文处理结果（文本格式）
        context_data: 上下文数据（文本格式）
        
    Returns:
        dict: 包含LLM分析提示词和相关数据
    """
    
    def generate_security_analysis_prompt(packet_info, context_info, global_stats):
        """生成网络安全深度分析提示词"""
        
        # 提取关键信息
        source_ip = packet_info.get('source_ip', 'unknown')
        attack_types = [attack['type'] for attack in packet_info.get('detected_attacks', [])]
        risk_level = packet_info.get('risk_assessment', {}).get('risk_level', 'low')
        risk_score = packet_info.get('risk_assessment', {}).get('risk_score', 0)
        
        # 构建上下文信息
        context_stats = packet_info.get('context_stats', {})
        request_frequency = context_stats.get('request_frequency_5min', 0)
        total_requests = context_stats.get('total_requests', 0)
        session_duration = context_stats.get('session_duration', 0)
        
        # 全局统计信息
        total_packets = global_stats.get('total_packets', 0)
        attack_packets = global_stats.get('attack_packets', 0)
        attack_rate = (attack_packets / max(total_packets, 1)) * 100
        
        prompt = f"""# 网络安全威胁深度分析任务

你是一位资深的网络安全专家，需要对以下检测到的网络威胁进行深度分析。

## 威胁概况
- **源IP地址**: {source_ip}
- **检测到的攻击类型**: {', '.join(attack_types) if attack_types else '无明确攻击类型'}
- **风险等级**: {risk_level}
- **风险评分**: {risk_score}/100
- **请求方法**: {packet_info.get('method', 'unknown')}
- **目标URL**: {packet_info.get('url', 'unknown')[:100]}{'...' if len(packet_info.get('url', '')) > 100 else ''}

## 行为模式分析
- **5分钟内请求频率**: {request_frequency:.1f} 次/分钟
- **总请求次数**: {total_requests}
- **会话持续时间**: {session_duration/60:.1f} 分钟
- **当前全局攻击率**: {attack_rate:.1f}%

## 攻击特征详情
"""
        
        # 添加具体的攻击特征
        for attack in packet_info.get('detected_attacks', []):
            prompt += f"""
### {attack['type'].upper()}攻击特征
- **匹配模式**: {attack['pattern']}
- **匹配内容**: {attack['matched_content']}
- **置信度**: {attack['confidence']:.1%}
"""
        
        # 添加历史攻击上下文
        recent_attacks = context_info.get('recent_attacks', [])[-5:]  # 最近5次攻击
        if recent_attacks:
            prompt += f"""
## 近期攻击历史
该IP地址近期攻击记录:
"""
            for i, attack in enumerate(recent_attacks, 1):
                prompt += f"- 攻击{i}: {attack.get('timestamp', '')} - {', '.join(attack.get('attack_types', []))}\n"
        
        prompt += f"""
## 分析要求

请基于以上信息进行专业的安全威胁分析，包括：

### 1. 威胁等级确认
- 确认或调整威胁等级（低风险/中风险/高风险/严重威胁）
- 说明等级判定的主要依据
- 评估误报概率（0-100%）

### 2. 攻击意图分析
- 分析攻击者的可能目标和动机
- 评估攻击的技术复杂度和专业程度
- 判断是否为自动化工具攻击

### 3. 影响评估
- 评估攻击成功可能造成的影响
- 分析可能的攻击扩散路径
- 评估对业务连续性的威胁

### 4. 应急响应建议
- **立即措施**: 需要立即执行的防护动作
- **短期措施**: 24小时内应采取的加固措施  
- **长期措施**: 持续改进的安全策略

### 5. 监控重点
- 建议重点监控的指标和行为
- 相关IP或攻击模式的追踪建议

## 分析原则
- 基于证据进行客观分析
- 考虑攻击的时间序列特征
- 结合全局攻击趋势进行判断
- 提供可操作的具体建议

请开始您的专业分析："""

        return prompt
    
    def generate_false_positive_analysis_prompt(packet_info, context_info):
        """生成误报分析提示词"""
        
        prompt = f"""# 网络安全检测误报分析

请分析以下检测结果是否可能存在误报：

## 检测结果
- **风险等级**: {packet_info.get('risk_assessment', {}).get('risk_level', 'unknown')}
- **检测到的攻击**: {[attack['type'] for attack in packet_info.get('detected_attacks', [])]}
- **请求URL**: {packet_info.get('url', '')[:200]}
- **请求频率**: {packet_info.get('context_stats', {}).get('request_frequency_5min', 0)} 次/分钟

## 误报分析要点

### 1. 业务合理性分析
- 该请求是否可能是正常业务操作？
- 是否存在合理的业务场景解释？

### 2. 技术实现合理性
- 检测到的"攻击特征"是否可能是正常技术实现？
- 是否存在开发测试等合理解释？

### 3. 行为模式分析
- 请求频率是否在正常范围内？
- 是否符合正常用户行为模式？

请提供：
1. **误报概率**: 0-100%
2. **分析依据**: 详细说明判断理由
3. **改进建议**: 如何减少类似误报

开始分析："""
        
        return prompt
    
    def determine_analysis_type(packet_info):
        """确定分析类型"""
        risk_level = packet_info.get('risk_assessment', {}).get('risk_level', 'low')
        detected_attacks = packet_info.get('detected_attacks', [])
        
        if risk_level in ['high', 'critical'] and detected_attacks:
            return 'security_analysis'
        elif risk_level == 'medium':
            return 'false_positive'  # 中风险需要误报分析
        else:
            return 'security_analysis'  # 默认安全分析
    
    # 主处理逻辑
    try:
        # 解析输入数据
        packet_result_data = json.loads(packet_result)
        context_data_parsed = json.loads(context_data) if context_data.strip() else {}
        
        # 提取处理结果
        processed_packet = packet_result_data.get('processed_packet', {})
        updated_context = packet_result_data.get('updated_context', {})
        
        # 检查是否需要LLM分析
        if not processed_packet.get('requires_llm_analysis', False):
            return {
                'output': json.dumps({
                    'skip_llm_analysis': True,
                    'reason': '风险等级较低，无需LLM深度分析',
                    'packet_result': processed_packet
                })
            }
        
        # 确定分析类型
        analysis_type = determine_analysis_type(processed_packet)
        
        # 生成相应的提示词
        if analysis_type == 'security_analysis':
            prompt = generate_security_analysis_prompt(
                processed_packet, 
                updated_context,
                updated_context.get('global_stats', {})
            )
        else:
            prompt = generate_false_positive_analysis_prompt(
                processed_packet,
                updated_context
            )
        
        # 构建LLM分析请求
        llm_request = {
            'analysis_type': analysis_type,
            'prompt': prompt,
            'packet_info': processed_packet,
            'context_summary': {
                'total_packets': updated_context.get('global_stats', {}).get('total_packets', 0),
                'attack_packets': updated_context.get('global_stats', {}).get('attack_packets', 0),
                'recent_attacks_count': len(updated_context.get('recent_attacks', [])),
                'analysis_timestamp': datetime.now().isoformat()
            }
        }
        
        return {
            'output': json.dumps(llm_request)
        }
        
    except Exception as e:
        return {
            'output': json.dumps({
                'error': True,
                'message': f"LLM分析准备失败: {str(e)}",
                'timestamp': datetime.now().isoformat()
            })
        }


# 测试代码
if __name__ == "__main__":
    # 测试用例
    test_packet_result = json.dumps({
        'processed_packet': {
            'source_ip': '192.168.1.100',
            'method': 'POST',
            'url': '/admin/login.php?id=1\' UNION SELECT * FROM users--',
            'is_attack': True,
            'detected_attacks': [
                {
                    'type': 'sql_injection',
                    'pattern': 'union\\s+select',
                    'matched_content': '/admin/login.php?id=1\' UNION SELECT * FROM users--',
                    'confidence': 0.8
                }
            ],
            'risk_assessment': {
                'risk_score': 75,
                'risk_level': 'high',
                'requires_llm_analysis': True
            },
            'context_stats': {
                'request_frequency_5min': 15.2,
                'total_requests': 45
            }
        },
        'updated_context': {
            'global_stats': {
                'total_packets': 100,
                'attack_packets': 12
            },
            'recent_attacks': []
        }
    })
    
    result = main(test_packet_result, "{}")
    print("LLM分析模块测试结果:")
    output = json.loads(result['output'])
    if 'prompt' in output:
        print("提示词长度:", len(output['prompt']))
        print("分析类型:", output['analysis_type'])
        print("提示词预览:")
        print(output['prompt'][:500] + "...")
    else:
        print(json.dumps(output, ensure_ascii=False, indent=2))