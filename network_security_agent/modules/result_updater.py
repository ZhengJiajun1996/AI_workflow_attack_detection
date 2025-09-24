"""
全量结果更新模块 (BH)
功能：将研判结果更新至返回变量
输入：all_detect_results (所有结果), detect_result (新结果), message_index (报文索引)
输出：更新后的结果列表
"""

def main(all_detect_results, detect_result, iteration_index):
    import json
    
    try:
        # 解析现有结果列表
        try:
            results_list = json.loads(all_detect_results) if all_detect_results else []
        except:
            results_list = []
        
        # 解析新的检测结果
        result_data = json.loads(detect_result)
        
        # 设置当前迭代索引
        result_data['iteration_index'] = int(iteration_index) if str(iteration_index).isdigit() else 0
        
        # 确保时间戳存在
        if 'timestamp' not in result_data:
            result_data['timestamp'] = ""
        
        # 添加处理元数据
        result_data['processing_metadata'] = {
            'processed_at': "",
            'result_id': f"RES_SEQ_{len(results_list) + 1}_{result_data['iteration_index']}",
            'sequence_number': len(results_list) + 1
        }
        
        # 验证结果完整性
        required_fields = ['iteration_index', 'timestamp', 'attack_flag', 'attack_type', 'risk_score']
        for field in required_fields:
            if field not in result_data:
                result_data[field] = None if field != 'attack_flag' else False
        
        # 添加到结果列表
        results_list.append(result_data)
        
        # 生成统计信息
        stats = _generate_statistics(results_list)
        result_data['session_statistics'] = stats
        
        return {
            "all_detect_results": json.dumps(results_list),
            "current_result": json.dumps(result_data)
        }
    except Exception as e:
        error_data = {
            'error': True,
            'message': str(e)
        }
        return {
            "all_detect_results": json.dumps(error_data)
        }

def _generate_statistics(results_list):
    """生成会话统计信息"""
    if not results_list:
        return {
            'total_messages': 0,
            'attack_messages': 0,
            'attack_rate': 0.0,
            'threat_distribution': {},
            'risk_score_distribution': {},
            'attack_types_summary': {},
            'processing_summary': {}
        }
    
    total_messages = len(results_list)
    attack_messages = sum(1 for r in results_list if r.get('attack_flag', False))
    attack_rate = (attack_messages / total_messages) * 100 if total_messages > 0 else 0
    
    # 威胁等级分布
    threat_distribution = {}
    for result in results_list:
        threat_level = result.get('threat_level', 'minimal')
        threat_distribution[threat_level] = threat_distribution.get(threat_level, 0) + 1
    
    # 风险评分分布
    risk_score_distribution = {
        '0-20': 0,
        '21-40': 0,
        '41-60': 0,
        '61-80': 0,
        '81-100': 0
    }
    
    for result in results_list:
        risk_score = result.get('risk_score', 0)
        if risk_score <= 20:
            risk_score_distribution['0-20'] = risk_score_distribution.get('0-20', 0) + 1
        elif risk_score <= 40:
            risk_score_distribution['21-40'] = risk_score_distribution.get('21-40', 0) + 1
        elif risk_score <= 60:
            risk_score_distribution['41-60'] = risk_score_distribution.get('41-60', 0) + 1
        elif risk_score <= 80:
            risk_score_distribution['61-80'] = risk_score_distribution.get('61-80', 0) + 1
        else:
            risk_score_distribution['81-100'] = risk_score_distribution.get('81-100', 0) + 1
    
    # 攻击类型统计
    attack_types_summary = {}
    for result in results_list:
        if result.get('attack_flag', False):
            attack_type = result.get('attack_type', 'unknown')
            attack_types_summary[attack_type] = attack_types_summary.get(attack_type, 0) + 1
    
    # 处理摘要
    processing_summary = {
        'rule_engine_count': sum(1 for r in results_list if r.get('detection_method') == 'rule_engine'),
        'llm_enhanced_count': sum(1 for r in results_list if r.get('detection_method') == 'llm_enhanced'),
        'fallback_count': sum(1 for r in results_list if 'fallback' in r.get('detection_method', '')),
        'average_confidence': sum(r.get('confidence', 0) for r in results_list) / total_messages if total_messages > 0 else 0,
        'average_risk_score': sum(r.get('risk_score', 0) for r in results_list) / total_messages if total_messages > 0 else 0
    }
    
    return {
        'total_messages': total_messages,
        'attack_messages': attack_messages,
        'attack_rate': round(attack_rate, 2),
        'threat_distribution': threat_distribution,
        'risk_score_distribution': risk_score_distribution,
        'attack_types_summary': attack_types_summary,
        'processing_summary': processing_summary
    }