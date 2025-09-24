"""
决策引擎模块 (BD)
功能：基于报文和辅助决策信息进行攻击检测
输入：message (报文), messages_infos (辅助决策信息)
输出：攻击标志、类型、风险评分、评估信息
"""

def main(message, messages_infos):
    import json
    import re
    import urllib.parse
    
    try:
        # 解析输入
        message_data = json.loads(message)
        current_message = message_data.get('message', '')
        
        if not current_message:
            return {
                'output': json.dumps({
                    'attack_flag': False,
                    'attack_type': 'none',
                    'risk_score': 0,
                    'risk_assessment': 'No message to analyze'
                })
            }
        
        # 解析辅助决策信息
        try:
            context = json.loads(messages_infos)
        except:
            context = {}
        
        # 扩展的攻击检测规则
        attack_patterns = {
            'sql_injection': [
                # 联合查询
                r'union\s+select',
                r'union\s+all\s+select',
                # 基本查询
                r'select\s+.*\s+from',
                r'select\s+.*\s+where',
                # 数据操作
                r'insert\s+into',
                r'update\s+.*\s+set',
                r'delete\s+from',
                r'drop\s+(table|database)',
                r'create\s+(table|database)',
                r'alter\s+table',
                # 盲注和报错注入
                r'and\s+\d+\s*=\s*\d+',
                r'or\s+\d+\s*=\s*\d+',
                r'and\s+1\s*=\s*1',
                r'or\s+1\s*=\s*1',
                # 时间盲注
                r'sleep\s*\(\s*\d+\s*\)',
                r'waitfor\s+delay',
                r'benchmark\s*\(',
                # 堆叠查询
                r';\s*(select|insert|update|delete|drop|create|alter)',
                # 注释绕过
                r'--\s*$',
                r'/\*.*\*/',
                # 引号绕过
                r'[\'"]\s*or\s*[\'"]',
                r'[\'"]\s*and\s*[\'"]',
                r'[\'"]\s*union\s*[\'"]',
                # 函数调用
                r'exec\s*\(',
                r'execute\s*\(',
                r'xp_cmdshell',
                r'sp_executesql'
            ],
            'xss': [
                # 脚本标签
                r'<script[^>]*>',
                r'<script[^>]*>.*?</script>',
                # 事件处理器
                r'on\w+\s*=',
                r'onload\s*=',
                r'onerror\s*=',
                r'onclick\s*=',
                r'onmouseover\s*=',
                # JavaScript协议
                r'javascript:',
                r'vbscript:',
                r'data:text/html',
                # iframe嵌入
                r'<iframe[^>]*>',
                r'<object[^>]*>',
                r'<embed[^>]*>',
                r'<applet[^>]*>',
                # 表单攻击
                r'<form[^>]*>',
                r'<input[^>]*>',
                # CSS表达式
                r'expression\s*\(',
                r'url\s*\(',
                # 编码绕过
                r'%3Cscript',
                r'%3Ciframe',
                r'\\x3Cscript',
                r'\\u003Cscript'
            ],
            'command_injection': [
                # 系统命令
                r'[;&|`$]',
                r'\\|\\|',
                r'&&',
                r'\\$\(',
                r'`[^`]*`',
                # Windows命令
                r'dir\s+',
                r'type\s+',
                r'del\s+',
                r'copy\s+',
                r'move\s+',
                r'net\s+',
                r'whoami',
                r'systeminfo',
                # Unix命令
                r'ls\s+',
                r'cat\s+',
                r'rm\s+',
                r'cp\s+',
                r'mv\s+',
                r'ps\s+',
                r'kill\s+',
                r'chmod\s+',
                r'chown\s+',
                # 危险命令
                r'rm\s+-rf',
                r'format\s+',
                r'fdisk',
                r'mkfs',
                # 管道和重定向
                r'\\|',
                r'>',
                r'>>',
                r'<',
                # 环境变量
                r'\\$\\w+',
                r'%\\w+%'
            ],
            'path_traversal': [
                # 相对路径
                r'\\.\\./',
                r'\\.\\.\\\\',
                # URL编码
                r'%2e%2e%2f',
                r'%2e%2e%5c',
                r'%252e%252e%252f',
                r'%252e%252e%255c',
                # 双编码
                r'%25252e%25252e%25252f',
                r'%25252e%25252e%25255c',
                # Unicode编码
                r'%c0%ae%c0%ae%c0%af',
                r'%c1%9c%c1%9c%c1%af',
                # 绝对路径
                r'/[a-zA-Z]:/',
                r'C:\\\\',
                r'/etc/',
                r'/var/',
                r'/tmp/',
                r'/home/',
                r'/root/',
                # 敏感文件
                r'passwd',
                r'shadow',
                r'hosts',
                r'hostname',
                r'issue',
                r'motd',
                r'profile',
                r'bashrc',
                r'ssh_config',
                r'httpd\\.conf',
                r'apache2\\.conf',
                r'nginx\\.conf',
                r'php\\.ini',
                r'my\\.cnf',
                r'web\\.config',
                r'web\\.xml'
            ],
            'ldap_injection': [
                r'\\*\\*',
                r'\\*\\(',
                r'\\)\\*',
                r'\\|\\(',
                r'\\)\\|',
                r'\\&\\(',
                r'\\)\\&',
                r'!\\(',
                r'\\)!',
                r'\\*\\*\\*',
                r'admin\\*',
                r'\\*admin',
                r'password\\*',
                r'\\*password'
            ],
            'xml_injection': [
                r'<!\\[CDATA\\[',
                r'\\]\\]>',
                r'<\\?xml',
                r'<!DOCTYPE',
                r'<!ENTITY',
                r'&\\w+;',
                r'%\\w+;',
                r'<\\w+[^>]*>',
                r'</\\w+>',
                r'xmlns:',
                r'xsi:',
                r'schemaLocation'
            ],
            'nosql_injection': [
                r'\\$where',
                r'\\$ne',
                r'\\$gt',
                r'\\$lt',
                r'\\$gte',
                r'\\$lte',
                r'\\$in',
                r'\\$nin',
                r'\\$regex',
                r'\\$exists',
                r'\\$or',
                r'\\$and',
                r'\\$not',
                r'\\$nor',
                r'\\$all',
                r'\\$elemMatch',
                r'\\$size',
                r'\\$type',
                r'\\$mod'
            ],
            'xxe_injection': [
                r'<!DOCTYPE',
                r'<!ENTITY',
                r'&\\w+;',
                r'%\\w+;',
                r'SYSTEM',
                r'PUBLIC',
                r'file://',
                r'http://',
                r'https://',
                r'ftp://',
                r'gopher://',
                r'jar://',
                r'netdoc://',
                r'php://',
                r'data://',
                r'zip://'
            ],
            'ssrf': [
                r'http://',
                r'https://',
                r'ftp://',
                r'gopher://',
                r'file://',
                r'ldap://',
                r'dict://',
                r'sftp://',
                r'tftp://',
                r'ldaps://',
                r'localhost',
                r'127\\.0\\.0\\.1',
                r'0\\.0\\.0\\.0',
                r'169\\.254',
                r'10\\.',
                r'172\\.(1[6-9]|2[0-9]|3[01])',
                r'192\\.168\\.',
                r'\\[::1\\]',
                r'\\[::\\]',
                r'metadata\\.googleapis\\.com',
                r'169\\.254\\.169\\.254'
            ],
            'csrf': [
                r'<form[^>]*action',
                r'<iframe[^>]*src',
                r'<img[^>]*src',
                r'<link[^>]*href',
                r'<script[^>]*src',
                r'XMLHttpRequest',
                r'fetch\\(',
                r'$.ajax',
                r'$.post',
                r'$.get',
                r'csrf_token',
                r'X-CSRF-Token',
                r'X-Requested-With'
            ],
            'file_upload': [
                r'\\.php\\?',
                r'\\.jsp\\?',
                r'\\.asp\\?',
                r'\\.aspx\\?',
                r'\\.exe\\?',
                r'\\.bat\\?',
                r'\\.cmd\\?',
                r'\\.scr\\?',
                r'\\.pif\\?',
                r'\\.com\\?',
                r'\\.sh\\?',
                r'\\.pl\\?',
                r'\\.py\\?',
                r'\\.rb\\?',
                r'\\.ps1\\?',
                r'\\.vbs\\?',
                r'\\.js\\?',
                r'\\.jar\\?',
                r'\\.war\\?'
            ]
        }
        
        # 检测攻击类型
        detected_attacks = []
        attack_details = {}
        
        for attack_type, patterns in attack_patterns.items():
            matches = []
            for pattern in patterns:
                if re.search(pattern, current_message, re.IGNORECASE):
                    matches.append(pattern)
            
            if matches:
                detected_attacks.append(attack_type)
                attack_details[attack_type] = {
                    'patterns_found': matches[:3],  # 只保留前3个匹配的模式
                    'confidence': min(len(matches) * 0.3, 1.0)
                }
        
        # 计算风险评分
        risk_score = 0
        risk_factors = []
        
        # 基于攻击模式评分
        if detected_attacks:
            base_score = 20  # 基础攻击分数
            type_multiplier = 1.5 if len(set(detected_attacks)) > 1 else 1.0  # 多种攻击类型倍增
            confidence_bonus = sum(details['confidence'] for details in attack_details.values()) * 10
            
            risk_score += base_score + (len(set(detected_attacks)) * 25 * type_multiplier) + confidence_bonus
            risk_factors.append(f'Detected attacks: {detected_attacks}')
        
        # 基于报文长度评分
        message_length = len(current_message)
        if message_length > 2000:
            risk_score += 25
            risk_factors.append('Very long message (>2000 chars)')
        elif message_length > 1000:
            risk_score += 15
            risk_factors.append('Long message (>1000 chars)')
        elif message_length > 500:
            risk_score += 8
            risk_factors.append('Moderate message length (>500 chars)')
        
        # 基于特殊字符评分
        special_chars = len(re.findall(r'[<>\"'\\\\&]', current_message))
        if special_chars > 20:
            risk_score += 20
            risk_factors.append('Very high special character count')
        elif special_chars > 10:
            risk_score += 12
            risk_factors.append('High special character count')
        elif special_chars > 5:
            risk_score += 6
            risk_factors.append('Moderate special character count')
        
        # 基于编码尝试评分
        encoding_patterns = len(re.findall(r'%[0-9a-fA-F]{2}|\\x[0-9a-fA-F]{2}|\\u[0-9a-fA-F]{4}', current_message))
        if encoding_patterns > 5:
            risk_score += 15
            risk_factors.append('Multiple encoding attempts')
        elif encoding_patterns > 2:
            risk_score += 8
            risk_factors.append('Encoding attempts detected')
        
        # 基于上下文信息评分
        if 'context_analysis' in context:
            recent_attack_rate = context['context_analysis'].get('recent_attack_rate', 0)
            if recent_attack_rate > 0.7:
                risk_score += 30
                risk_factors.append('Very high recent attack rate')
            elif recent_attack_rate > 0.5:
                risk_score += 20
                risk_factors.append('High recent attack rate')
            elif recent_attack_rate > 0.3:
                risk_score += 10
                risk_factors.append('Moderate recent attack rate')
            
            # 时间分析
            time_analysis = context['context_analysis'].get('time_based_analysis', {})
            messages_per_minute = time_analysis.get('messages_per_minute', 0)
            if messages_per_minute > 50:
                risk_score += 15
                risk_factors.append('High frequency requests')
            elif messages_per_minute > 20:
                risk_score += 8
                risk_factors.append('Elevated request frequency')
        
        # 基于统计信息评分
        if 'statistics' in context:
            stats = context['statistics']
            total_messages = stats.get('total_messages', 0)
            attack_patterns_count = len([p for p, count in stats.get('attack_patterns', {}).items() if count > 0])
            
            if attack_patterns_count > 3:
                risk_score += 15
                risk_factors.append('Multiple attack patterns in session')
            elif attack_patterns_count > 1:
                risk_score += 8
                risk_factors.append('Multiple attack patterns detected')
            
            # 消息长度异常
            if total_messages > 10:
                avg_length = sum(stats.get('message_lengths', [0])) / len(stats.get('message_lengths', [1]))
                if message_length > avg_length * 2:
                    risk_score += 10
                    risk_factors.append('Message length significantly above average')
        
        # 限制风险评分在0-100之间
        risk_score = min(max(risk_score, 0), 100)
        
        # 确定攻击类型
        if detected_attacks:
            if len(detected_attacks) == 1:
                attack_type = detected_attacks[0]
            else:
                # 选择置信度最高的攻击类型
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
        
        return {
            'output': json.dumps({
                'attack_flag': attack_flag,
                'attack_type': attack_type,
                'risk_score': risk_score,
                'risk_assessment': risk_assessment,
                'detected_attacks': detected_attacks,
                'attack_details': attack_details,
                'risk_factors': risk_factors,
                'confidence': max([details['confidence'] for details in attack_details.values()], default=0.0)
            })
        }
    except Exception as e:
        return {
            'output': json.dumps({
                'error': True,
                'message': str(e)
            })
        }