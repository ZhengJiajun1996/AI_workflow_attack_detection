#!/usr/bin/env python3
"""
网络攻击检测智能体 - 循环体模块测试示例
演示新架构的完整工作流程
"""

import json
import sys
import os
from datetime import datetime

# 添加项目路径
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# 导入循环体模块
from loop_modules.packet_processor import main as packet_processor_main
from loop_modules.llm_analyzer import main as llm_analyzer_main
from loop_modules.response_generator import main as response_generator_main


def test_loop_workflow():
    """测试循环体工作流"""
    print("=" * 80)
    print("网络攻击检测智能体 - 循环体模块测试")
    print("=" * 80)
    print()
    
    # 准备测试报文列表
    test_packets = [
        {
            "timestamp": "2024-01-15T10:30:00Z",
            "source_ip": "192.168.1.100",
            "method": "POST",
            "url": "/login.php?id=1' UNION SELECT user,password FROM users--",
            "headers": {
                "Host": "example.com",
                "User-Agent": "sqlmap/1.6.12",
                "Content-Type": "application/x-www-form-urlencoded"
            },
            "body": "username=admin&password=' OR '1'='1-- "
        },
        {
            "timestamp": "2024-01-15T10:31:00Z",
            "source_ip": "192.168.1.100",
            "method": "GET",
            "url": "/admin/users.php?action=delete&id=1",
            "headers": {
                "Host": "example.com",
                "User-Agent": "sqlmap/1.6.12"
            },
            "body": ""
        },
        {
            "timestamp": "2024-01-15T10:32:00Z",
            "source_ip": "192.168.1.101",
            "method": "GET",
            "url": "/products/laptop-dell-xps13",
            "headers": {
                "Host": "example.com",
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
            },
            "body": ""
        },
        {
            "timestamp": "2024-01-15T10:33:00Z",
            "source_ip": "203.0.113.45",
            "method": "GET",
            "url": "/search.php?q=<script>alert('XSS')</script>",
            "headers": {
                "Host": "example.com",
                "User-Agent": "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1)"
            },
            "body": ""
        }
    ]
    
    # 初始化上下文数据
    context_data = {
        'ip_stats': {},
        'global_stats': {
            'total_packets': 0,
            'attack_packets': 0,
            'start_time': datetime.now().timestamp()
        },
        'recent_attacks': [],
        'final_results': []
    }
    
    print(f"开始处理 {len(test_packets)} 个报文...")
    print()
    
    # 模拟循环体处理
    for i, packet in enumerate(test_packets, 1):
        print(f"处理报文 {i}/{len(test_packets)}")
        print(f"  源IP: {packet['source_ip']}")
        print(f"  URL: {packet['url'][:60]}...")
        
        # 步骤1: 报文处理
        print("  🔄 步骤1: 报文处理...")
        packet_result = packet_processor_main(
            json.dumps(packet), 
            json.dumps(context_data)
        )
        
        packet_result_data = json.loads(packet_result['output'])
        
        if packet_result_data.get('error'):
            print(f"    ❌ 处理失败: {packet_result_data.get('message')}")
            continue
        
        processed_packet = packet_result_data['processed_packet']
        updated_context = packet_result_data['updated_context']
        
        print(f"    ✅ 攻击检测: {'是' if processed_packet['is_attack'] else '否'}")
        if processed_packet['detected_attacks']:
            attack_types = [attack['type'] for attack in processed_packet['detected_attacks']]
            print(f"    ✅ 攻击类型: {', '.join(attack_types)}")
        print(f"    ✅ 风险等级: {processed_packet['risk_assessment']['risk_level']}")
        print(f"    ✅ 风险评分: {processed_packet['risk_assessment']['risk_score']}/100")
        
        # 步骤2: 判断是否需要LLM分析
        requires_llm = processed_packet.get('requires_llm_analysis', False)
        llm_analysis_result = None
        
        if requires_llm:
            print("  🤖 步骤2: LLM深度分析...")
            
            # 准备LLM分析
            llm_analyzer_result = llm_analyzer_main(
                packet_result['output'],
                json.dumps(updated_context)
            )
            
            llm_analyzer_data = json.loads(llm_analyzer_result['output'])
            
            if llm_analyzer_data.get('skip_llm_analysis'):
                print("    ℹ️ 跳过LLM分析（风险等级较低）")
                llm_analysis_result = llm_analyzer_result['output']
            else:
                # 模拟LLM分析结果
                llm_analysis_result = json.dumps({
                    'analysis_result': f"经过深度分析，确认检测结果准确。这是一次{processed_packet['risk_assessment']['risk_level']}等级的威胁，建议采取相应的防护措施。"
                })
                print(f"    ✅ LLM分析完成")
        else:
            print("  ℹ️ 步骤2: 跳过LLM分析（风险等级较低）")
            llm_analysis_result = ""
        
        # 步骤3: 生成最终响应
        print("  📋 步骤3: 生成安全响应...")
        response_result = response_generator_main(
            packet_result['output'],
            llm_analysis_result or ""
        )
        
        response_data = json.loads(response_result['output'])
        
        if response_data.get('error'):
            print(f"    ❌ 响应生成失败: {response_data.get('message')}")
            continue
        
        print(f"    ✅ 最终威胁等级: {response_data['threat_assessment']['final_threat_level']}")
        print(f"    ✅ 响应动作: {response_data['response_action']['description']}")
        
        # 更新上下文数据（模拟循环变量更新）
        updated_context['final_results'].append(response_data)
        context_data = updated_context
        
        print(f"    ✅ 上下文已更新")
        print()
    
    # 生成最终统计报告
    print("📊 生成最终统计报告...")
    
    total_packets = context_data['global_stats']['total_packets']
    attack_packets = context_data['global_stats']['attack_packets']
    attack_rate = (attack_packets / max(total_packets, 1)) * 100
    
    # 统计威胁分布
    threat_distribution = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
    attack_types_summary = {}
    affected_ips = set()
    
    for result in context_data['final_results']:
        threat_level = result.get('threat_assessment', {}).get('final_threat_level', 'low')
        threat_distribution[threat_level] += 1
        
        if result.get('threat_assessment', {}).get('is_attack'):
            ip = result.get('technical_details', {}).get('source_ip', 'unknown')
            affected_ips.add(ip)
            
            attack_types = result.get('threat_assessment', {}).get('attack_types', [])
            for attack_type in attack_types:
                attack_types_summary[attack_type] = attack_types_summary.get(attack_type, 0) + 1
    
    print()
    print("=" * 60)
    print("最终统计报告")
    print("=" * 60)
    print(f"总处理报文数: {total_packets}")
    print(f"检测到攻击数: {attack_packets}")
    print(f"攻击检出率: {attack_rate:.1f}%")
    print(f"涉及IP数量: {len(affected_ips)}")
    print()
    print("威胁等级分布:")
    for level, count in threat_distribution.items():
        if count > 0:
            print(f"  {level.upper()}: {count} 个")
    print()
    
    if attack_types_summary:
        print("攻击类型分布:")
        for attack_type, count in attack_types_summary.items():
            print(f"  {attack_type}: {count} 次")
        print()
    
    print("涉及的IP地址:")
    for ip in affected_ips:
        print(f"  - {ip}")
    
    print()
    print("✅ 循环体工作流测试完成！")
    
    return context_data['final_results']


def test_individual_modules():
    """测试单个模块功能"""
    print("\n" + "=" * 80)
    print("单个模块功能测试")
    print("=" * 80)
    
    # 测试报文处理模块
    print("\n1. 测试报文处理模块")
    print("-" * 40)
    
    test_packet = json.dumps({
        "timestamp": "2024-01-15T10:30:00Z",
        "source_ip": "192.168.1.100",
        "method": "POST",
        "url": "/login.php?id=1' OR 1=1--",
        "headers": {
            "User-Agent": "sqlmap/1.6.12",
            "Content-Type": "application/x-www-form-urlencoded"
        },
        "body": "username=admin&password=' OR '1'='1-- "
    })
    
    result = packet_processor_main(test_packet, "{}")
    result_data = json.loads(result['output'])
    
    if result_data.get('error'):
        print(f"❌ 测试失败: {result_data.get('message')}")
    else:
        processed = result_data['processed_packet']
        print(f"✅ 报文ID: {processed['packet_id']}")
        print(f"✅ 攻击检测: {processed['is_attack']}")
        print(f"✅ 风险评分: {processed['risk_assessment']['risk_score']}")
        
        if processed['detected_attacks']:
            print("✅ 检测到的攻击:")
            for attack in processed['detected_attacks']:
                print(f"   - {attack['type']}: {attack['confidence']:.1%}")


if __name__ == "__main__":
    # 运行测试
    test_individual_modules()
    final_results = test_loop_workflow()
    
    print(f"\n🎯 测试总结: 成功处理了 {len(final_results)} 个报文的完整分析流程")