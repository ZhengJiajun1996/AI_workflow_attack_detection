#!/usr/bin/env python3
"""
网络安全检测智能体 - 完整演示示例
展示整个工作流的端到端执行过程
"""

import json
import sys
import os
from datetime import datetime

# 添加项目路径
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, project_root)

# 直接导入模块文件并执行其中的函数
import importlib.util

def load_module_from_file(file_path, module_name):
    """从文件路径加载模块"""
    spec = importlib.util.spec_from_file_location(module_name, file_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

# 加载各个模块
packet_input_module = load_module_from_file(
    os.path.join(project_root, 'modules', 'packet_input.py'), 
    'packet_input'
)
context_module = load_module_from_file(
    os.path.join(project_root, 'modules', 'context_feature_extraction.py'),
    'context_feature_extraction'  
)
rule_engine_module = load_module_from_file(
    os.path.join(project_root, 'modules', 'rule_engine_scanner.py'),
    'rule_engine_scanner'
)
prompts_module = load_module_from_file(
    os.path.join(project_root, 'prompts', 'llm_analysis_prompts.py'),
    'llm_analysis_prompts'
)
response_module = load_module_from_file(
    os.path.join(project_root, 'modules', 'response_generator.py'),
    'response_generator'
)

# 获取函数引用
execute_packet_input = packet_input_module.execute_packet_input
execute_context_feature_extraction = context_module.execute_context_feature_extraction  
execute_rule_engine_scan = rule_engine_module.execute_rule_engine_scan
generate_llm_prompt = prompts_module.generate_llm_prompt
generate_security_response = response_module.generate_security_response


class NetworkSecurityAgentDemo:
    """网络安全检测智能体演示"""
    
    def __init__(self):
        self.demo_cases = self._prepare_demo_cases()
    
    def _prepare_demo_cases(self):
        """准备演示用例"""
        return [
            {
                "name": "SQL注入攻击",
                "description": "典型的SQL注入攻击尝试",
                "input_data": {
                    "timestamp": "2024-01-15T10:30:00Z",
                    "source_ip": "192.168.1.100",
                    "destination_ip": "10.0.0.1",
                    "source_port": 54321,
                    "destination_port": 80,
                    "method": "POST",
                    "url": "/admin/login.php?id=1' UNION SELECT user,password FROM users--",
                    "headers": {
                        "Host": "vulnerable-site.com",
                        "User-Agent": "sqlmap/1.6.12#dev (http://sqlmap.org)",
                        "Content-Type": "application/x-www-form-urlencoded",
                        "Content-Length": "45",
                        "Cookie": "session=abc123"
                    },
                    "body": "username=admin&password=' OR '1'='1'-- "
                }
            },
            {
                "name": "XSS攻击",
                "description": "跨站脚本攻击尝试",
                "input_data": {
                    "timestamp": "2024-01-15T10:35:00Z",
                    "source_ip": "203.0.113.45",
                    "destination_ip": "10.0.0.1",
                    "source_port": 45678,
                    "destination_port": 80,
                    "method": "GET",
                    "url": "/search.php?q=<script>alert('XSS')</script>",
                    "headers": {
                        "Host": "vulnerable-site.com",
                        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                        "Referer": "javascript:alert(document.cookie)"
                    },
                    "body": ""
                }
            },
            {
                "name": "DDoS攻击模拟",
                "description": "高频请求模拟DDoS攻击",
                "input_data": {
                    "timestamp": "2024-01-15T10:40:00Z",
                    "source_ip": "198.51.100.10",
                    "destination_ip": "10.0.0.1",
                    "source_port": 12345,
                    "destination_port": 80,
                    "method": "GET",
                    "url": "/index.html",
                    "headers": {
                        "Host": "target-site.com",
                        "User-Agent": "Mozilla/5.0",
                        "Connection": "keep-alive"
                    },
                    "body": ""
                },
                "context_simulation": {
                    "high_frequency": True,
                    "requests_per_minute": 150
                }
            },
            {
                "name": "正常请求",
                "description": "正常的用户请求",
                "input_data": {
                    "timestamp": "2024-01-15T10:45:00Z",
                    "source_ip": "192.168.1.50",
                    "destination_ip": "10.0.0.1",
                    "source_port": 56789,
                    "destination_port": 80,
                    "method": "GET",
                    "url": "/products/laptop-dell-xps13",
                    "headers": {
                        "Host": "ecommerce-site.com",
                        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
                        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                        "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
                        "Accept-Encoding": "gzip, deflate, br",
                        "Referer": "https://ecommerce-site.com/search?q=laptop",
                        "Cookie": "user_session=xyz789; preferences=lang_zh"
                    },
                    "body": ""
                }
            }
        ]
    
    def run_complete_demo(self):
        """运行完整演示"""
        print("=" * 80)
        print("网络安全检测智能体 - 完整演示")
        print("=" * 80)
        print()
        
        for i, case in enumerate(self.demo_cases, 1):
            print(f"演示案例 {i}: {case['name']}")
            print(f"描述: {case['description']}")
            print("-" * 60)
            
            try:
                # 执行完整的检测流程
                result = self._execute_detection_workflow(case)
                
                # 显示结果摘要
                self._display_result_summary(result)
                
            except Exception as e:
                print(f"❌ 执行失败: {str(e)}")
            
            print("\n" + "=" * 80 + "\n")
    
    def _execute_detection_workflow(self, case):
        """执行完整的检测工作流"""
        print("🔄 开始执行检测工作流...")
        
        # 1. 报文输入模块
        print("📥 步骤1: 报文输入处理...")
        packet_result = execute_packet_input(json.dumps(case['input_data']))
        packet_data = json.loads(packet_result)
        
        if packet_data.get('error'):
            raise Exception(f"报文处理失败: {packet_data.get('error_message')}")
        
        print(f"   ✅ 报文ID: {packet_data.get('packet_id')}")
        print(f"   ✅ 源IP: {packet_data.get('source_ip')}")
        print(f"   ✅ 请求: {packet_data.get('method')} {packet_data.get('url')[:50]}...")
        
        # 2. 上下文特征提取模块
        print("🔍 步骤2: 上下文特征提取...")
        context_result = execute_context_feature_extraction(packet_result)
        context_data = json.loads(context_result)
        
        if context_data.get('error'):
            raise Exception(f"特征提取失败: {context_data.get('error_message')}")
        
        risk_score = context_data.get('risk_indicators', {}).get('risk_score', 0)
        print(f"   ✅ 风险评分: {risk_score}/100")
        print(f"   ✅ 请求频率: {context_data.get('ip_features', {}).get('request_frequency_5min', 0)} 次/分钟")
        
        # 模拟高频请求场景
        if case.get('context_simulation', {}).get('high_frequency'):
            print("   🔄 模拟高频请求场景...")
            # 修改上下文数据以模拟高频攻击
            context_data['time_features'] = {
                'requests_last_1min': 150,
                'requests_last_5min': 600,
                'requests_last_1hour': 5000,
                'is_burst_pattern': True
            }
            context_data['risk_indicators']['risk_score'] = 90
            context_data['risk_indicators']['risk_factors'] = ['high_frequency_requests', 'burst_pattern']
            context_result = json.dumps(context_data)
        
        # 3. 规则引擎扫描模块
        print("🛡️ 步骤3: 规则引擎扫描...")
        rule_result = execute_rule_engine_scan(packet_result, context_result)
        rule_data = json.loads(rule_result)
        
        if rule_data.get('error'):
            raise Exception(f"规则引擎扫描失败: {rule_data.get('error_message')}")
        
        is_attack = rule_data.get('is_attack', False)
        risk_level = rule_data.get('risk_level', '低风险')
        confidence = rule_data.get('confidence_score', 0.0)
        
        print(f"   ✅ 攻击检测: {'是' if is_attack else '否'}")
        print(f"   ✅ 风险等级: {risk_level}")
        print(f"   ✅ 置信度: {confidence:.1%}")
        
        if rule_data.get('attack_types'):
            print(f"   ✅ 攻击类型: {', '.join(rule_data.get('attack_types', []))}")
        
        # 4. 判断是否需要LLM分析
        requires_llm = rule_data.get('requires_llm_analysis', False)
        llm_analysis_result = None
        
        if requires_llm or risk_level in ['高风险', '严重']:
            print("🤖 步骤4: LLM深度分析...")
            
            # 生成LLM提示词
            llm_prompt = generate_llm_prompt(packet_result, context_result, rule_result)
            
            # 模拟LLM分析结果（在实际部署中，这里会调用真实的LLM API）
            llm_analysis_result = self._simulate_llm_analysis(case, rule_data)
            print(f"   ✅ LLM分析完成")
            print(f"   ✅ 分析长度: {len(llm_analysis_result)} 字符")
        else:
            print("ℹ️ 步骤4: 跳过LLM分析（风险等级较低）")
            llm_analysis_result = {"content": "风险等级较低，无需深度分析"}
        
        # 5. 生成最终安全响应
        print("📋 步骤5: 生成安全响应...")
        response_result = generate_security_response(
            json.dumps(llm_analysis_result),
            packet_result,
            context_result,
            rule_result
        )
        response_data = json.loads(response_result)
        
        if response_data.get('error'):
            raise Exception(f"响应生成失败: {response_data.get('error_message')}")
        
        print("   ✅ 安全响应生成完成")
        
        return {
            'packet_data': packet_data,
            'context_data': context_data,
            'rule_data': rule_data,
            'llm_analysis': llm_analysis_result,
            'response_data': response_data
        }
    
    def _simulate_llm_analysis(self, case, rule_data):
        """模拟LLM分析结果"""
        case_name = case['name']
        
        if case_name == "SQL注入攻击":
            return {
                "content": """### 威胁概况评估
检测到严重的SQL注入攻击，威胁等级：**严重威胁**。
误报概率：5%

### 攻击向量分析
攻击者使用联合查询（UNION SELECT）技术尝试从数据库中提取敏感信息，包括用户名和密码。
攻击工具：sqlmap自动化SQL注入工具
技术水平：中级到高级

### 影响评估
如果攻击成功，可能导致：
- 数据库中所有用户凭据泄露
- 管理员账户被盗用
- 整个应用系统被完全控制

### 防护建议
立即措施：
- 立即阻断攻击源IP
- 检查数据库访问日志
- 验证现有用户账户安全性

短期措施：
- 实施SQL查询参数化
- 加强输入验证和过滤
- 启用数据库活动监控"""
            }
        
        elif case_name == "XSS攻击":
            return {
                "content": """### 威胁概况评估
检测到跨站脚本攻击，威胁等级：**高风险**。
误报概率：10%

### 攻击向量分析
攻击者尝试注入JavaScript代码以窃取用户Cookie或执行恶意操作。
使用了多重编码和伪协议绕过技术。

### 影响评估
可能导致用户会话劫持、敏感信息泄露、恶意代码执行。

### 防护建议
- 启用内容安全策略(CSP)
- 实施严格的输入输出过滤
- 对用户输入进行HTML编码"""
            }
        
        elif case_name == "DDoS攻击模拟":
            return {
                "content": """### 威胁概况评估
检测到分布式拒绝服务攻击，威胁等级：**严重威胁**。
误报概率：15%

### 攻击向量分析
高频率请求攻击，每分钟超过150次请求，远超正常用户行为。
可能是僵尸网络发起的协调攻击。

### 影响评估
可能导致服务不可用、系统资源耗尽、正常用户无法访问。

### 防护建议
- 启用流量清洗和限流
- 实施IP黑名单机制
- 扩展服务器处理能力"""
            }
        
        else:  # 正常请求
            return {
                "content": """### 威胁概况评估
经过深度分析，确认为正常的用户请求，威胁等级：**无威胁**。
误报概率：2%

### 行为分析
用户行为模式正常，访问路径合理，请求频率在正常范围内。

### 建议
继续正常监控，无需特殊处置。"""
            }
    
    def _display_result_summary(self, result):
        """显示结果摘要"""
        response_data = result['response_data']
        threat_assessment = response_data.get('threat_assessment', {})
        
        print("\n📊 检测结果摘要:")
        print(f"   响应ID: {response_data.get('response_id')}")
        print(f"   是否恶意: {'是' if threat_assessment.get('is_malicious') else '否'}")
        print(f"   威胁等级: {threat_assessment.get('threat_level', '未知')}")
        print(f"   置信度: {threat_assessment.get('confidence_score', 0):.1%}")
        
        if threat_assessment.get('attack_types'):
            print(f"   攻击类型: {', '.join(threat_assessment.get('attack_types', []))}")
        
        # 显示响应动作
        response_action = response_data.get('response_action', {})
        print(f"\n🎯 响应动作:")
        print(f"   动作: {response_action.get('description', '未知')}")
        print(f"   优先级: {response_action.get('priority', '未知')}")
        print(f"   自动执行: {'是' if response_action.get('auto_execute') else '否'}")
        
        # 显示执行摘要
        executive_summary = response_data.get('executive_summary', '')
        if executive_summary:
            print(f"\n📋 执行摘要:")
            print(f"   {executive_summary}")
        
        # 显示防护建议（仅显示立即措施）
        protection_recs = response_data.get('protection_recommendations', {})
        immediate_actions = protection_recs.get('immediate', [])
        if immediate_actions:
            print(f"\n🛡️ 立即防护措施:")
            for action in immediate_actions[:3]:  # 只显示前3条
                print(f"   • {action}")
        
        # 显示处理性能
        metrics = response_data.get('metrics', {})
        processing_time = metrics.get('processing_time_ms', 0)
        print(f"\n⏱️ 处理性能:")
        print(f"   处理时间: {processing_time:.1f}ms")
        print(f"   触发规则数: {metrics.get('detection_rules_triggered', 0)}")


def main():
    """主函数"""
    demo = NetworkSecurityAgentDemo()
    demo.run_complete_demo()


if __name__ == "__main__":
    main()