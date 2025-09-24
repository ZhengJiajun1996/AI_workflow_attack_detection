"""
决策引擎模块 (BD)
功能：基于报文和辅助决策信息进行攻击检测
输入：message (报文), messages_infos (辅助决策信息)
输出：攻击标志、类型、风险评分、评估信息
"""

def main(message_data, messages_infos):
    import json
    import re
    
    try:
        # 解析输入
        message_info = json.loads(message_data)
        current_message = message_info.get('message', '')
        
        if not current_message:
            decision_result = {
                'attack_flag': False,
                'attack_type': 'none',
                'risk_score': 0,
                'risk_assessment': 'No message to analyze'
            }
            return {
                "decision_result": json.dumps(decision_result),
                "risk_score": 0,
                "attack_flag": False
            }
        
        # 解析辅助决策信息
        try:
            context = json.loads(messages_infos)
        except:
            context = {}
        
        # 简化的攻击检测规则
        attack_patterns = {
            'sql_injection': [
                r'union\s+select',
                r'select\s+.*\s+from',
                r'insert\s+into',
                r'delete\s+from',
                r'drop\s+table',
                r"'\s*or\s*'",
                r"'\s*and\s*'",
                r'--',
                r'/\*.*\*/'
            ],
            'xss': [
                r'<script[^>]*>',
                r'javascript:',
                r'on\w+\s*=',
                r'<iframe[^>]*>',
                r'<object[^>]*>'
            ],
            'command_injection': [
                r'[;&|`$]',
                r'\|\|',
                r'&&',
                r'\$\(',
                r'`[^`]*`'
            ],
            'path_traversal': [
                r'\.\.\/',
                r'\.\.\\\\',
                r'%2e%2e%2f',
                r'%2e%2e%5c'
            ]
        }
        
        # 检测攻击类型
        detected_attacks = []
        attack_details = {}
        
        for attack_type, patterns in attack_patterns.items():
            matches = []
            for pattern in patterns:
                try:
                    if re.search(pattern, current_message, re.IGNORECASE):
                        matches.append(pattern)
                except re.error:
                    # 跳过有问题的正则表达式
                    continue
            
            if matches:
                detected_attacks.append(attack_type)
                attack_details[attack_type] = {
                    'patterns_found': matches[:3],
                    'confidence': min(len(matches) * 0.3, 1.0)
                }
        
        # 计算风险评分
        risk_score = 0
        risk_factors = []
        
        # 基于攻击模式评分
        if detected_attacks:
            base_score = 20
            type_multiplier = 1.5 if len(set(detected_attacks)) > 1 else 1.0
            confidence_bonus = sum(details['confidence'] for details in attack_details.values()) * 10
            
            risk_score = risk_score + base_score + (len(set(detected_attacks)) * 25 * type_multiplier) + confidence_bonus
            risk_factors.append(f'Detected attacks: {detected_attacks}')
        
        # 基于报文长度评分
        message_length = len(current_message)
        if message_length > 2000:
            risk_score = risk_score + 25
            risk_factors.append('Very long message')
        elif message_length > 1000:
            risk_score = risk_score + 15
            risk_factors.append('Long message')
        elif message_length > 500:
            risk_score = risk_score + 8
            risk_factors.append('Moderate message length')
        
        # 基于特殊字符评分
        special_chars = len(re.findall(r'[<>"&\\\\]', current_message))
        if special_chars > 20:
            risk_score = risk_score + 20
            risk_factors.append('Very high special character count')
        elif special_chars > 10:
            risk_score = risk_score + 12
            risk_factors.append('High special character count')
        elif special_chars > 5:
            risk_score = risk_score + 6
            risk_factors.append('Moderate special character count')
        
        # 基于编码尝试评分
        encoding_patterns = len(re.findall(r'%[0-9a-fA-F]{2}', current_message))
        if encoding_patterns > 5:
            risk_score = risk_score + 15
            risk_factors.append('Multiple encoding attempts')
        elif encoding_patterns > 2:
            risk_score = risk_score + 8
            risk_factors.append('Encoding attempts detected')
        
        # 基于上下文信息评分
        if 'context_analysis' in context:
            recent_attack_rate = context['context_analysis'].get('recent_attack_rate', 0)
            if recent_attack_rate > 0.7:
                risk_score = risk_score + 30
                risk_factors.append('Very high recent attack rate')
            elif recent_attack_rate > 0.5:
                risk_score = risk_score + 20
                risk_factors.append('High recent attack rate')
            elif recent_attack_rate > 0.3:
                risk_score = risk_score + 10
                risk_factors.append('Moderate recent attack rate')
        
        # 限制风险评分在0-100之间
        risk_score = min(max(risk_score, 0), 100)
        
        # 确定攻击类型
        if detected_attacks:
            if len(detected_attacks) == 1:
                attack_type = detected_attacks[0]
            else:
                attack_type = max(attack_details.keys(), key=lambda x: attack_details[x]['confidence'])
                if len(detected_attacks) > 2:
                    attack_type = 'multiple'
            attack_flag = True
        else:
            attack_type = 'none'
            attack_flag = False
        
        # 生成风险评估
        if risk_score >= 90:
            risk_level = 'critical'
        elif risk_score >= 70:
            risk_level = 'high'
        elif risk_score >= 50:
            risk_level = 'medium'
        elif risk_score >= 30:
            risk_level = 'low'
        else:
            risk_level = 'minimal'
        
        risk_assessment = f'Risk level: {risk_level}, Score: {risk_score}. Factors: {risk_factors}'
        
        decision_result = {
            'attack_flag': attack_flag,
            'attack_type': attack_type,
            'risk_score': risk_score,
            'risk_assessment': risk_assessment,
            'detected_attacks': detected_attacks,
            'attack_details': attack_details,
            'risk_factors': risk_factors,
            'confidence': max([details['confidence'] for details in attack_details.values()], default=0.0)
        }
        
        return {
            "decision_result": json.dumps(decision_result),
            "risk_score": risk_score,
            "attack_flag": attack_flag
        }
    except Exception as e:
        error_data = {
            'error': True,
            'message': str(e)
        }
        return {
            "decision_result": json.dumps(error_data),
            "risk_score": 0,
            "attack_flag": False
        }