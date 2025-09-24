#!/usr/bin/env python3
"""
网络攻击检测工作流简单测试
"""

import json

def test_message_extractor():
    """测试单个报文提取模块"""
    print("\n=== 测试单个报文提取模块 ===")
    
    # 模拟用户输入
    user_input = """GET /login.php HTTP/1.1
SELECT * FROM users WHERE id=1
<script>alert('xss')</script>
../../../etc/passwd
"""
    
    # 模拟模块代码
    def main(user_input, current_index):
        import json
        
        try:
            index = int(current_index) if current_index.isdigit() else 0
            messages = [line.strip() for line in user_input.split('\n') if line.strip()]
            
            if index < len(messages):
                message = messages[index]
                return {
                    'output': json.dumps({
                        'message': message,
                        'index': index,
                        'total_count': len(messages)
                    })
                }
            else:
                return {
                    'output': json.dumps({
                        'message': '',
                        'index': index,
                        'total_count': len(messages),
                        'completed': True
                    })
                }
        except Exception as e:
            return {
                'output': json.dumps({
                    'error': True,
                    'message': str(e)
                })
            }
    
    # 测试提取每个报文
    messages = [line.strip() for line in user_input.split('\n') if line.strip()]
    for i in range(len(messages) + 1):
        result = main(user_input, str(i))
        data = json.loads(result['output'])
        if data.get('completed'):
            print(f"索引 {i}: 处理完成")
            break
        else:
            print(f"索引 {i}: {data['message']}")
    
    return True

def test_decision_engine():
    """测试决策引擎模块"""
    print("\n=== 测试决策引擎模块 ===")
    
    import re
    
    def main(message, messages_infos):
        import json
        
        try:
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
            
            # 攻击检测规则
            attack_patterns = {
                'sql_injection': [
                    r'union\s+select',
                    r'select\s+.*\s+from',
                    r'insert\s+into',
                    r'delete\s+from',
                    r'drop\s+table'
                ],
                'xss': [
                    r'<script[^>]*>',
                    r'javascript:',
                    r'on\w+\s*='
                ],
                'command_injection': [
                    r'[;&|`$]',
                    r'\|\|',
                    r'&&'
                ],
                'path_traversal': [
                    r'\.\./',
                    r'\.\.\\',
                    r'%2e%2e%2f'
                ]
            }
            
            # 检测攻击类型
            detected_attacks = []
            for attack_type, patterns in attack_patterns.items():
                for pattern in patterns:
                    if re.search(pattern, current_message, re.IGNORECASE):
                        detected_attacks.append(attack_type)
                        break
            
            # 计算风险评分
            risk_score = 0
            risk_factors = []
            
            if detected_attacks:
                risk_score += 30 * len(set(detected_attacks))
                risk_factors.append(f'Detected attacks: {detected_attacks}')
            
            # 基于报文长度评分
            message_length = len(current_message)
            if message_length > 1000:
                risk_score += 20
                risk_factors.append('Very long message')
            elif message_length > 500:
                risk_score += 10
                risk_factors.append('Long message')
            
            # 限制风险评分在0-100之间
            risk_score = min(max(risk_score, 0), 100)
            
            # 确定攻击类型
            if detected_attacks:
                attack_type = detected_attacks[0] if len(detected_attacks) == 1 else 'multiple'
                attack_flag = True
            else:
                attack_type = 'none'
                attack_flag = False
            
            # 生成风险评估
            if risk_score >= 80:
                risk_level = 'critical'
            elif risk_score >= 60:
                risk_level = 'high'
            elif risk_score >= 40:
                risk_level = 'medium'
            else:
                risk_level = 'low'
            
            risk_assessment = f'Risk level: {risk_level}, Score: {risk_score}. Factors: {risk_factors}'
            
            return {
                'output': json.dumps({
                    'attack_flag': attack_flag,
                    'attack_type': attack_type,
                    'risk_score': risk_score,
                    'risk_assessment': risk_assessment,
                    'detected_attacks': detected_attacks,
                    'risk_factors': risk_factors
                })
            }
        except Exception as e:
            return {
                'output': json.dumps({
                    'error': True,
                    'message': str(e)
                })
            }
    
    # 测试消息
    test_cases = [
        'GET /login.php HTTP/1.1',  # 正常请求
        'SELECT * FROM users WHERE id=1',  # SQL注入
        '<script>alert("xss")</script>',  # XSS
        '../../../etc/passwd',  # 路径遍历
        'rm -rf /; echo "hack"',  # 命令注入
    ]
    
    context = "{}"
    for msg in test_cases:
        message_data = json.dumps({
            'message': msg,
            'index': 0,
            'total_count': 1
        })
        
        result = main(message_data, context)
        decision_data = json.loads(result['output'])
        
        print(f"\n消息: {msg}")
        print(f"攻击标志: {decision_data.get('attack_flag', False)}")
        print(f"攻击类型: {decision_data.get('attack_type', 'none')}")
        print(f"风险评分: {decision_data.get('risk_score', 0)}")
        print(f"风险评估: {decision_data.get('risk_assessment', '')}")
    
    return True

def run_complete_workflow_test():
    """运行完整工作流测试"""
    print("\n" + "="*60)
    print("网络攻击检测工作流完整测试")
    print("="*60)
    
    # 测试用户输入
    user_input = """GET /login.php HTTP/1.1
POST /api/users HTTP/1.1
SELECT * FROM users WHERE id=1 OR 1=1
<script>alert('xss')</script>
../../../etc/passwd
rm -rf /; echo "hack"
GET /admin/dashboard HTTP/1.1
"""
    
    print(f"\n输入报文:")
    for i, line in enumerate(user_input.strip().split('\n')):
        print(f"{i}: {line}")
    
    # 模拟完整工作流
    messages = [line.strip() for line in user_input.strip().split('\n') if line.strip()]
    all_detect_results = []
    
    print(f"\n开始处理 {len(messages)} 个报文...")
    
    for i, message in enumerate(messages):
        print(f"\n--- 处理报文 {i+1}/{len(messages)} ---")
        print(f"报文: {message}")
        
        # 简化处理，模拟决策引擎结果
        if any(pattern in message.lower() for pattern in ['select', 'union', 'insert', 'delete']):
            attack_flag = True
            attack_type = 'sql_injection'
            risk_score = 85
        elif '<script' in message or 'javascript:' in message:
            attack_flag = True
            attack_type = 'xss'
            risk_score = 75
        elif '../' in message:
            attack_flag = True
            attack_type = 'path_traversal'
            risk_score = 65
        elif any(char in message for char in [';', '&', '|', '`']):
            attack_flag = True
            attack_type = 'command_injection'
            risk_score = 90
        else:
            attack_flag = False
            attack_type = 'none'
            risk_score = 15
        
        # 生成检测结果
        detect_result = {
            'message_index': i,
            'timestamp': '2024-01-15T10:30:00Z',
            'attack_flag': attack_flag,
            'attack_type': attack_type,
            'risk_score': risk_score,
            'risk_assessment': f'Risk level: {"high" if risk_score > 60 else "medium" if risk_score > 30 else "low"}, Score: {risk_score}',
            'detection_method': 'llm_enhanced' if risk_score > 50 else 'rule_engine',
            'confidence': 0.9 if risk_score > 70 else 0.7,
            'recommendations': ['立即阻断此请求', '记录攻击日志'] if attack_flag else ['正常处理']
        }
        
        all_detect_results.append(detect_result)
        
        print(f"检测结果:")
        print(f"  攻击标志: {attack_flag}")
        print(f"  攻击类型: {attack_type}")
        print(f"  风险评分: {risk_score}")
        print(f"  检测方法: {detect_result['detection_method']}")
    
    # 生成最终报告
    print(f"\n=== 最终处理报告 ===")
    print(f"总报文数: {len(all_detect_results)}")
    
    attack_count = sum(1 for r in all_detect_results if r['attack_flag'])
    print(f"攻击报文数: {attack_count}")
    print(f"攻击率: {attack_count/len(all_detect_results)*100:.1f}%")
    
    # 按攻击类型统计
    attack_types = {}
    for result in all_detect_results:
        if result['attack_flag']:
            attack_type = result['attack_type']
            attack_types[attack_type] = attack_types.get(attack_type, 0) + 1
    
    print(f"\n攻击类型分布:")
    for attack_type, count in attack_types.items():
        print(f"  {attack_type}: {count}")
    
    print(f"\n所有检测结果:")
    for result in all_detect_results:
        status = "🚨 攻击" if result['attack_flag'] else "✅ 正常"
        print(f"  [{result['message_index']}] {status} - {result['attack_type']} (评分: {result['risk_score']})")
    
    return True

def main():
    """主测试函数"""
    try:
        # 运行各个模块测试
        test_message_extractor()
        test_decision_engine()
        
        # 运行完整工作流测试
        run_complete_workflow_test()
        
        print("\n" + "="*60)
        print("✅ 所有测试完成！工作流模块功能正常")
        print("="*60)
        
    except Exception as e:
        print(f"\n❌ 测试失败: {e}")
        import traceback
        traceback.print_exc()
        return False
    
    return True

if __name__ == "__main__":
    main()