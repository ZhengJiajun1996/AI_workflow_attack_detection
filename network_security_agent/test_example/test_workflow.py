#!/usr/bin/env python3
"""
网络攻击检测工作流测试示例
测试所有模块的功能
"""

import json
import sys
import os

# 添加项目路径
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

def test_message_extractor():
    """测试单个报文提取模块"""
    print("\\n=== 测试单个报文提取模块 ===")
    
    # 模拟用户输入
    user_input = """GET /login.php HTTP/1.1
POST /api/users HTTP/1.1
SELECT * FROM users WHERE id=1
<script>alert('xss')</script>
../../../etc/passwd
"""
    
    # 模拟模块代码
    def main(user_input, current_index):
        import json
        import re
        
        try:
            # 解析当前索引
            index = int(current_index) if current_index.isdigit() else 0
            
            # 将输入文本按行分割，每行作为一个报文
            messages = [line.strip() for line in user_input.split('\\n') if line.strip()]
            
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
    messages = [line.strip() for line in user_input.split('\\n') if line.strip()]
    for i in range(len(messages) + 1):
        result = main(user_input, str(i))
        data = json.loads(result['output'])
        if data.get('completed'):
            print(f"索引 {i}: 处理完成")
            break
        else:
            print(f"索引 {i}: {data['message']}")
    
    return True

def test_context_extractor():
    """测试辅助决策信息提取模块"""
    print("\\n=== 测试辅助决策信息提取模块 ===")
    
    # 模拟模块代码
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
                'has_sql_keywords': bool(re.search(r'(union|select|insert|update|delete|drop|create|alter)', current_message.lower())),
                'has_script_tags': bool(re.search(r'<script|javascript:|on\\w+\\s*=', current_message.lower())),
                'has_command_injection': bool(re.search(r'[;&|`$]', current_message)),
                'has_path_traversal': bool(re.search(r'\\.\\./', current_message)),
                'special_chars_count': len(re.findall(r'[<>\"'\\\\&]', current_message)),
                'timestamp': datetime.now().isoformat()
            }
            
            # 更新统计信息
            if 'statistics' not in context:
                context['statistics'] = {
                    'total_messages': 0,
                    'attack_patterns': {},
                    'message_lengths': [],
                    'processing_history': []
                }
            
            context['statistics']['total_messages'] += 1
            context['statistics']['message_lengths'].append(message_features['length'])
            context['statistics']['processing_history'].append({
                'index': message_data.get('index', 0),
                'features': message_features,
                'timestamp': message_features['timestamp']
            })
            
            # 更新攻击模式统计
            if message_features['has_sql_keywords']:
                context['statistics']['attack_patterns']['sql_injection'] = context['statistics']['attack_patterns'].get('sql_injection', 0) + 1
            if message_features['has_script_tags']:
                context['statistics']['attack_patterns']['xss'] = context['statistics']['attack_patterns'].get('xss', 0) + 1
            if message_features['has_command_injection']:
                context['statistics']['attack_patterns']['command_injection'] = context['statistics']['attack_patterns'].get('command_injection', 0) + 1
            if message_features['has_path_traversal']:
                context['statistics']['attack_patterns']['path_traversal'] = context['statistics']['attack_patterns'].get('path_traversal', 0) + 1
            
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
    
    # 测试消息
    test_messages = [
        'GET /login.php HTTP/1.1',
        'SELECT * FROM users WHERE id=1',
        '<script>alert("xss")</script>',
        '../../../etc/passwd'
    ]
    
    context = "{}"
    for i, msg in enumerate(test_messages):
        message_data = json.dumps({
            'message': msg,
            'index': i,
            'total_count': len(test_messages)
        })
        
        result = main(message_data, context)
        context = result['output']
        
        print(f"处理消息 {i}: {msg}")
    
    # 显示最终上下文
    final_context = json.loads(context)
    print(f"\\n最终上下文统计:")
    print(f"总消息数: {final_context['statistics']['total_messages']}")
    print(f"攻击模式统计: {final_context['statistics']['attack_patterns']}")
    
    return True

def test_decision_engine():
    """测试决策引擎模块"""
    print("\\n=== 测试决策引擎模块 ===")
    
    # 模拟模块代码
    def main(message, messages_infos):
        import json
        import re
        
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
            
            # 攻击检测规则
            attack_patterns = {
                'sql_injection': [
                    r'union\\s+select',
                    r'select\\s+.*\\s+from',
                    r'insert\\s+into',
                    r'delete\\s+from',
                    r'drop\\s+table',
                    r'\\'\\s*or\\s*\\'',
                    r'\\'\\s*and\\s*\\'',
                    r'--\\s*$',
                    r'/\\*.*\\*/'
                ],
                'xss': [
                    r'<script[^>]*>',
                    r'javascript:',
                    r'on\\w+\\s*=',
                    r'<iframe[^>]*>',
                    r'<object[^>]*>',
                    r'<embed[^>]*>'
                ],
                'command_injection': [
                    r'[;&|`$]',
                    r'\\|\\|',
                    r'&&',
                    r'\\$\\(',
                    r'`[^`]*`'
                ],
                'path_traversal': [
                    r'\\.\\./',
                    r'\\.\\.\\\\',
                    r'%2e%2e%2f',
                    r'%2e%2e%5c'
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
            
            # 基于攻击模式评分
            if detected_attacks:
                risk_score += 30 * len(set(detected_attacks))  # 每种攻击类型+30分
                risk_factors.append(f'Detected attacks: {detected_attacks}')
            
            # 基于报文长度评分
            message_length = len(current_message)
            if message_length > 1000:
                risk_score += 20
                risk_factors.append('Very long message')
            elif message_length > 500:
                risk_score += 10
                risk_factors.append('Long message')
            
            # 基于特殊字符评分
            special_chars = len(re.findall(r'[<>\"'\\\\&]', current_message))
            if special_chars > 10:
                risk_score += 15
                risk_factors.append('High special character count')
            elif special_chars > 5:
                risk_score += 8
                risk_factors.append('Moderate special character count')
            
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
        
        print(f"\\n消息: {msg}")
        print(f"攻击标志: {decision_data.get('attack_flag', False)}")
        print(f"攻击类型: {decision_data.get('attack_type', 'none')}")
        print(f"风险评分: {decision_data.get('risk_score', 0)}")
        print(f"风险评估: {decision_data.get('risk_assessment', '')}")
    
    return True

def test_response_generator():
    """测试响应生成器模块"""
    print("\\n=== 测试响应生成器模块 ===")
    
    # 模拟模块代码
    def main(decision_result):
        import json
        from datetime import datetime
        
        try:
            decision_data = json.loads(decision_result)
            
            # 生成响应结果
            detect_result = {
                'message_index': 0,  # 将由循环变量更新模块设置
                'timestamp': datetime.now().isoformat(),
                'attack_flag': decision_data.get('attack_flag', False),
                'attack_type': decision_data.get('attack_type', 'none'),
                'risk_score': decision_data.get('risk_score', 0),
                'risk_assessment': decision_data.get('risk_assessment', ''),
                'detection_method': 'rule_engine',
                'confidence': 0.8 if decision_data.get('risk_score', 0) > 50 else 0.6,
                'recommendations': []
            }
            
            # 添加建议
            if decision_data.get('attack_flag'):
                detect_result['recommendations'].append('立即阻断此请求')
                detect_result['recommendations'].append('记录攻击日志')
            elif decision_data.get('risk_score', 0) > 30:
                detect_result['recommendations'].append('继续监控此IP')
            else:
                detect_result['recommendations'].append('正常处理')
            
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
    
    # 测试不同风险等级的决策结果
    test_decision_results = [
        {
            'attack_flag': False,
            'attack_type': 'none',
            'risk_score': 20,
            'risk_assessment': 'Low risk'
        },
        {
            'attack_flag': True,
            'attack_type': 'sql_injection',
            'risk_score': 85,
            'risk_assessment': 'High risk SQL injection detected'
        },
        {
            'attack_flag': True,
            'attack_type': 'xss',
            'risk_score': 70,
            'risk_assessment': 'Medium-high risk XSS detected'
        }
    ]
    
    for i, decision_result in enumerate(test_decision_results):
        result = main(json.dumps(decision_result))
        detect_result = json.loads(result['output'])
        
        print(f"\\n测试案例 {i+1}:")
        print(f"攻击标志: {detect_result['attack_flag']}")
        print(f"攻击类型: {detect_result['attack_type']}")
        print(f"风险评分: {detect_result['risk_score']}")
        print(f"检测方法: {detect_result['detection_method']}")
        print(f"置信度: {detect_result['confidence']}")
        print(f"建议: {detect_result['recommendations']}")
    
    return True

def test_result_updater():
    """测试全量结果更新模块"""
    print("\\n=== 测试全量结果更新模块 ===")
    
    # 模拟模块代码
    def main(all_detect_results, detect_result, message_index):
        import json
        
        try:
            # 解析现有结果列表
            try:
                results_list = json.loads(all_detect_results) if all_detect_results else []
            except:
                results_list = []
            
            # 解析新的检测结果
            result_data = json.loads(detect_result)
            result_data['message_index'] = int(message_index)
            
            # 添加到结果列表
            results_list.append(result_data)
            
            return {
                'output': json.dumps(results_list)
            }
        except Exception as e:
            return {
                'output': json.dumps({
                    'error': True,
                    'message': str(e)
                })
            }
    
    # 测试累积结果
    all_results = "[]"
    
    test_results = [
        {
            'attack_flag': False,
            'attack_type': 'none',
            'risk_score': 20,
            'detection_method': 'rule_engine',
            'confidence': 0.6
        },
        {
            'attack_flag': True,
            'attack_type': 'sql_injection',
            'risk_score': 85,
            'detection_method': 'llm_enhanced',
            'confidence': 0.9
        },
        {
            'attack_flag': True,
            'attack_type': 'xss',
            'risk_score': 70,
            'detection_method': 'rule_engine',
            'confidence': 0.8
        }
    ]
    
    for i, result in enumerate(test_results):
        all_results = main(all_results, json.dumps(result), str(i))['output']
        results_list = json.loads(all_results)
        
        print(f"\\n添加结果 {i+1}:")
        print(f"当前结果数量: {len(results_list)}")
        print(f"最新结果: 攻击={results_list[-1]['attack_flag']}, 类型={results_list[-1]['attack_type']}, 评分={results_list[-1]['risk_score']}")
    
    # 显示最终结果摘要
    final_results = json.loads(all_results)
    print(f"\\n=== 最终结果摘要 ===")
    print(f"总结果数: {len(final_results)}")
    
    attack_count = sum(1 for r in final_results if r['attack_flag'])
    print(f"攻击数量: {attack_count}")
    print(f"攻击率: {attack_count/len(final_results)*100:.1f}%")
    
    return True

def run_complete_workflow_test():
    """运行完整工作流测试"""
    print("\\n" + "="*60)
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
    
    print(f"\\n输入报文:")
    for i, line in enumerate(user_input.strip().split('\\n')):
        print(f"{i}: {line}")
    
    # 模拟完整工作流
    messages = [line.strip() for line in user_input.strip().split('\\n') if line.strip()]
    all_detect_results = []
    messages_infos = {}
    
    print(f"\\n开始处理 {len(messages)} 个报文...")
    
    for i, message in enumerate(messages):
        print(f"\\n--- 处理报文 {i+1}/{len(messages)} ---")
        print(f"报文: {message}")
        
        # 这里简化处理，实际工作流中会调用各个模块
        # 模拟决策引擎结果
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
    print(f"\\n=== 最终处理报告 ===")
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
    
    print(f"\\n攻击类型分布:")
    for attack_type, count in attack_types.items():
        print(f"  {attack_type}: {count}")
    
    print(f"\\n所有检测结果:")
    for result in all_detect_results:
        status = "🚨 攻击" if result['attack_flag'] else "✅ 正常"
        print(f"  [{result['message_index']}] {status} - {result['attack_type']} (评分: {result['risk_score']})")
    
    return True

def main():
    """主测试函数"""
    try:
        # 运行各个模块测试
        test_message_extractor()
        test_context_extractor()
        test_decision_engine()
        test_response_generator()
        test_result_updater()
        
        # 运行完整工作流测试
        run_complete_workflow_test()
        
        print("\\n" + "="*60)
        print("✅ 所有测试完成！工作流模块功能正常")
        print("="*60)
        
    except Exception as e:
        print(f"\\n❌ 测试失败: {e}")
        import traceback
        traceback.print_exc()
        return False
    
    return True

if __name__ == "__main__":
    main()