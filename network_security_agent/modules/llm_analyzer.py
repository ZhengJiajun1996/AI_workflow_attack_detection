"""
LLM攻击分析模块 (BG)
功能：为高风险报文准备LLM分析提示词
输入：message (报文), messages_infos (辅助决策信息), decision_result (决策结果)
输出：LLM分析提示词和相关元数据
"""

def main(message_data, messages_infos, decision_result):
    import json
    
    try:
        # 解析输入
        message_info = json.loads(message_data)
        decision_data = json.loads(decision_result)
        
        current_message = message_info.get('message', '')
        detected_attacks = decision_data.get('detected_attacks', [])
        attack_details = decision_data.get('attack_details', {})
        risk_factors = decision_data.get('risk_factors', [])
        
        # 解析上下文信息
        try:
            context = json.loads(messages_infos)
            context_analysis = context.get('context_analysis', {})
            statistics = context.get('statistics', {})
        except:
            context = {}
            context_analysis = {}
            statistics = {}
        
        # 生成详细的LLM分析提示词
        prompt = f"""你是一位资深的网络安全专家，请对以下网络请求进行深度安全分析：

## 请求信息
请求内容：{current_message}
请求长度：{len(current_message)} 字符

## 当前检测结果
- 攻击标志：{decision_data.get('attack_flag', False)}
- 攻击类型：{decision_data.get('attack_type', 'none')}
- 风险评分：{decision_data.get('risk_score', 0)}/100
- 风险评估：{decision_data.get('risk_assessment', '')}
- 检测到的攻击类型：{detected_attacks}
- 风险因素：{risk_factors}

## 攻击详情分析
"""
        
        # 添加攻击详情
        if attack_details:
            prompt += "\n### 检测到的攻击模式：\n"
            for attack_type, details in attack_details.items():
                prompt += f"- {attack_type.upper()}:\n"
                prompt += f"  - 匹配模式：{details.get('patterns_found', [])}\n"
                prompt += f"  - 置信度：{details.get('confidence', 0):.2f}\n"
        
        # 添加上下文分析
        if context_analysis:
            prompt += f"""
## 上下文分析
- 近期攻击率：{context_analysis.get('recent_attack_rate', 0):.2%}
- 平均报文长度：{context_analysis.get('average_message_length', 0):.0f} 字符
- 模式一致性：{context_analysis.get('pattern_consistency', False)}
- 每分钟请求数：{context_analysis.get('time_based_analysis', {}).get('messages_per_minute', 0)}
- 可疑模式：{context_analysis.get('time_based_analysis', {}).get('suspicious_patterns', [])}
"""
        
        # 添加统计信息
        if statistics:
            prompt += f"""
## 会话统计信息
- 总报文数：{statistics.get('total_messages', 0)}
- 攻击模式统计：{statistics.get('attack_patterns', {})}
- 处理历史：{len(statistics.get('processing_history', []))} 条记录
"""
        
        prompt += f"""
## 分析要求
请基于以上信息进行深度安全分析，特别关注：

1. **攻击确认**：确认是否真的存在安全威胁
2. **威胁等级**：评估实际威胁程度
3. **攻击向量**：分析可能的攻击路径和目的
4. **影响评估**：评估攻击成功后的潜在影响
5. **误报分析**：判断是否为误报
6. **防护建议**：提供具体的防护措施

## 输出格式要求
请以JSON格式返回分析结果：

{{
  "attack_flag": true/false,
  "attack_type": "具体攻击类型或none",
  "risk_score": 0-100的评分,
  "risk_assessment": "详细的风险评估说明",
  "confidence": 0.0-1.0的置信度,
  "threat_level": "minimal/low/medium/high/critical",
  "attack_vector": "攻击向量描述",
  "potential_impact": "潜在影响分析",
  "false_positive": true/false,
  "analysis_reasoning": "分析推理过程",
  "recommendations": [
    "具体建议1",
    "具体建议2"
  ],
  "immediate_actions": [
    "立即执行的操作1",
    "立即执行的操作2"
  ]
}}

请确保分析结果准确、专业，并提供可操作的建议。"""

        llm_data = {
            'prompt': prompt,
            'message_data': message_info,
            'decision_data': decision_data,
            'context_summary': {
                'recent_attack_rate': context_analysis.get('recent_attack_rate', 0),
                'total_messages': statistics.get('total_messages', 0),
                'attack_patterns': statistics.get('attack_patterns', {}),
                'suspicious_patterns': context_analysis.get('time_based_analysis', {}).get('suspicious_patterns', [])
            },
            'analysis_metadata': {
                'message_length': len(current_message),
                'detected_attacks_count': len(detected_attacks),
                'risk_factors_count': len(risk_factors),
                'confidence_threshold': 0.7
            }
        }
        
        return {
            "prompt": prompt,
            "llm_data": json.dumps(llm_data)
        }
    except Exception as e:
        error_data = {
            'error': True,
            'message': str(e)
        }
        return {
            "prompt": "Error in LLM analyzer",
            "llm_data": json.dumps(error_data)
        }