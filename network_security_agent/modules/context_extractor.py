"""
辅助决策信息提取模块 (BB)
功能：提取和更新辅助决策信息
输入：message (当前报文), messages_infos (历史信息)
输出：更新后的辅助决策信息
"""

def main(message, messages_infos):
    import json
    import re
    from datetime import datetime
    
    try:
        # 解析输入
        message_data = json.loads(message)
        current_message = message_data.get('message', '')
        
        if not current_message:
            return {'output': json.dumps(messages_infos)}
        
        # 解析现有辅助决策信息
        try:
            context = json.loads(messages_infos) if messages_infos else {}
        except:
            context = {}
        
        # 提取报文特征
        message_features = {
            'length': len(current_message),
            'has_sql_keywords': bool(re.search(r'(union|select|insert|update|delete|drop|create|alter|exec|execute)', current_message.lower())),
            'has_script_tags': bool(re.search(r'<script|javascript:|on\w+\s*=|vbscript:|data:', current_message.lower())),
            'has_command_injection': bool(re.search(r'[;&|`$]|\\|\\||&&', current_message)),
            'has_path_traversal': bool(re.search(r'\\.\\./|\\.\\.\\\\|%2e%2e%2f|%2e%2e%5c', current_message.lower())),
            'has_xss_patterns': bool(re.search(r'<[^>]*>|javascript:|on\w+\s*=|vbscript:', current_message.lower())),
            'has_injection_patterns': bool(re.search(r'[\'\"][\s]*or[\s]*[\'\"]|[\'\"][\s]*and[\s]*[\'\"]|--|\/\*|\*\/', current_message.lower())),
            'has_encoding_attempts': bool(re.search(r'%[0-9a-fA-F]{2}|\\x[0-9a-fA-F]{2}|\\u[0-9a-fA-F]{4}', current_message)),
            'special_chars_count': len(re.findall(r'[<>\"'\\\\&]', current_message)),
            'timestamp': datetime.now().isoformat()
        }
        
        # 更新统计信息
        if 'statistics' not in context:
            context['statistics'] = {
                'total_messages': 0,
                'attack_patterns': {},
                'message_lengths': [],
                'processing_history': [],
                'ip_analysis': {},
                'session_analysis': {},
                'time_analysis': {}
            }
        
        context['statistics']['total_messages'] += 1
        context['statistics']['message_lengths'].append(message_features['length'])
        context['statistics']['processing_history'].append({
            'index': message_data.get('index', 0),
            'features': message_features,
            'timestamp': message_features['timestamp']
        })
        
        # 更新攻击模式统计
        attack_patterns = {
            'sql_injection': message_features['has_sql_keywords'] or message_features['has_injection_patterns'],
            'xss': message_features['has_script_tags'] or message_features['has_xss_patterns'],
            'command_injection': message_features['has_command_injection'],
            'path_traversal': message_features['has_path_traversal'],
            'encoding_attempts': message_features['has_encoding_attempts']
        }
        
        for pattern, detected in attack_patterns.items():
            if detected:
                context['statistics']['attack_patterns'][pattern] = context['statistics']['attack_patterns'].get(pattern, 0) + 1
        
        # 计算上下文关联信息
        recent_messages = context['statistics']['processing_history'][-10:]  # 最近10条
        if len(recent_messages) > 1:
            recent_attacks = sum(1 for msg in recent_messages if any(msg['features'].get(f'has_{pattern}', False) for pattern in ['sql_keywords', 'script_tags', 'command_injection', 'path_traversal']))
            
            context['context_analysis'] = {
                'recent_attack_rate': recent_attacks / len(recent_messages),
                'average_message_length': sum(msg['features']['length'] for msg in recent_messages) / len(recent_messages),
                'pattern_consistency': len(set(msg['features'].get('has_sql_keywords', False) for msg in recent_messages)) == 1,
                'time_based_analysis': {
                    'messages_per_minute': len([m for m in recent_messages if (datetime.now() - datetime.fromisoformat(m['timestamp'].replace('Z', '+00:00'))).seconds < 60]),
                    'suspicious_patterns': [p for p, count in context['statistics']['attack_patterns'].items() if count > 0]
                }
            }
        
        # 保留最近100条历史记录
        if len(context['statistics']['processing_history']) > 100:
            context['statistics']['processing_history'] = context['statistics']['processing_history'][-100:]
        if len(context['statistics']['message_lengths']) > 200:
            context['statistics']['message_lengths'] = context['statistics']['message_lengths'][-200:]
        
        return {
            'output': json.dumps(context)
        }
    except Exception as e:
        return {
            'output': json.dumps({
                'error': True,
                'message': str(e)
            })
        }