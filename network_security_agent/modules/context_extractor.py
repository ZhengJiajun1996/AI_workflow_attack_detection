"""
辅助决策信息提取模块 (BB)
功能：提取和更新辅助决策信息
输入：message (当前报文), messages_infos (历史信息)
输出：更新后的辅助决策信息
"""

def main(message_data, messages_infos):
    import json
    import re
    
    try:
        # 解析输入
        message_info = json.loads(message_data)
        current_message = message_info.get('message', '')
        
        if not current_message:
            return {
                "messages_infos": json.dumps(messages_infos)
            }
        
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
            'special_chars_count': len(re.findall(r'[<>"&\\\\]', current_message)),
            'timestamp': None
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
        
        # 平台限制：不允许对对象项使用增强赋值(+=)。改为显式读取-计算-写入
        current_total = context['statistics'].get('total_messages', 0)
        context['statistics']['total_messages'] = current_total + 1
        context['statistics']['message_lengths'].append(message_features['length'])
        context['statistics']['processing_history'].append({
            'iteration_index': message_info.get('iteration_index', 0),
            'features': message_features,
            'timestamp': message_features['timestamp']
        })
        
        # 更新攻击模式统计（避免 dict 迭代）
        if message_features.get('has_sql_keywords', False) or message_features.get('has_injection_patterns', False):
            context['statistics']['attack_patterns']['sql_injection'] = context['statistics']['attack_patterns'].get('sql_injection', 0) + 1
        if message_features.get('has_script_tags', False) or message_features.get('has_xss_patterns', False):
            context['statistics']['attack_patterns']['xss'] = context['statistics']['attack_patterns'].get('xss', 0) + 1
        if message_features.get('has_command_injection', False):
            context['statistics']['attack_patterns']['command_injection'] = context['statistics']['attack_patterns'].get('command_injection', 0) + 1
        if message_features.get('has_path_traversal', False):
            context['statistics']['attack_patterns']['path_traversal'] = context['statistics']['attack_patterns'].get('path_traversal', 0) + 1
        if message_features.get('has_encoding_attempts', False):
            context['statistics']['attack_patterns']['encoding_attempts'] = context['statistics']['attack_patterns'].get('encoding_attempts', 0) + 1
        
        # 计算上下文关联信息（避免切片、生成器、字典迭代）
        ph = context['statistics']['processing_history']
        ph_len = len(ph)
        recent_messages = []
        if ph_len > 0:
            start_idx = ph_len - 10
            if start_idx < 0:
                start_idx = 0
            idx = start_idx
            while idx < ph_len:
                recent_messages.append(ph[idx])
                idx = idx + 1
        if len(recent_messages) > 1:
            # 统计最近攻击数
            recent_attacks = 0
            i = 0
            check_keys = ['sql_keywords', 'script_tags', 'command_injection', 'path_traversal']
            while i < len(recent_messages):
                msg = recent_messages[i]
                has_attack = False
                j = 0
                while j < len(check_keys):
                    key = 'has_' + check_keys[j]
                    if msg.get('features', {}).get(key, False):
                        has_attack = True
                        break
                    j = j + 1
                if has_attack:
                    recent_attacks = recent_attacks + 1
                i = i + 1

            # 平均消息长度
            total_len = 0
            k = 0
            while k < len(recent_messages):
                total_len = total_len + recent_messages[k].get('features', {}).get('length', 0)
                k = k + 1
            average_length = (float(total_len) / float(len(recent_messages))) if len(recent_messages) > 0 else 0.0

            # has_sql_keywords 一致性
            all_same = True
            if len(recent_messages) > 0:
                first_val = bool(recent_messages[0].get('features', {}).get('has_sql_keywords', False))
                t = 1
                while t < len(recent_messages):
                    if bool(recent_messages[t].get('features', {}).get('has_sql_keywords', False)) != first_val:
                        all_same = False
                        break
                    t = t + 1

            # 可疑模式（显式检查已知键，避免 dict 迭代）
            suspicious_patterns = []
            if context['statistics']['attack_patterns'].get('sql_injection', 0) > 0:
                suspicious_patterns.append('sql_injection')
            if context['statistics']['attack_patterns'].get('xss', 0) > 0:
                suspicious_patterns.append('xss')
            if context['statistics']['attack_patterns'].get('command_injection', 0) > 0:
                suspicious_patterns.append('command_injection')
            if context['statistics']['attack_patterns'].get('path_traversal', 0) > 0:
                suspicious_patterns.append('path_traversal')
            if context['statistics']['attack_patterns'].get('encoding_attempts', 0) > 0:
                suspicious_patterns.append('encoding_attempts')

            context['context_analysis'] = {
                'recent_attack_rate': (float(recent_attacks) / float(len(recent_messages))) if len(recent_messages) > 0 else 0.0,
                'average_message_length': average_length,
                'pattern_consistency': all_same,
                'time_based_analysis': {
                    'messages_per_minute': 0,
                    'suspicious_patterns': suspicious_patterns
                }
            }
        
        # 保留最近100条历史记录
        if len(context['statistics']['processing_history']) > 100:
            context['statistics']['processing_history'] = context['statistics']['processing_history'][-100:]
        if len(context['statistics']['message_lengths']) > 200:
            context['statistics']['message_lengths'] = context['statistics']['message_lengths'][-200:]
        
        return {
            "messages_infos": json.dumps(context)
        }
    except Exception as e:
        error_data = {
            'error': True,
            'message': str(e)
        }
        return {
            "messages_infos": json.dumps(error_data)
        }