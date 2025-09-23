"""
网络安全检测智能体 - LLM深度研判模块提示词
工作流编排中的LLM模块使用的提示词模板
"""

def get_security_analysis_prompt(packet_data: dict, context_features: dict, rule_engine_result: dict) -> str:
    """
    生成网络安全深度分析的提示词
    
    Args:
        packet_data: 报文数据
        context_features: 上下文特征
        rule_engine_result: 规则引擎检测结果
        
    Returns:
        str: 格式化的提示词
    """
    
    prompt = f"""# 网络安全威胁深度分析任务

你是一位资深的网络安全专家，需要对以下网络流量进行深度安全分析。请基于提供的数据进行全面的威胁评估。

## 分析数据

### 1. HTTP报文信息
- **请求方法**: {packet_data.get('method', 'N/A')}
- **请求URL**: {packet_data.get('url', 'N/A')}
- **源IP地址**: {packet_data.get('source_ip', 'N/A')}
- **User-Agent**: {packet_data.get('user_agent', 'N/A')}
- **请求头部**: {packet_data.get('headers', {})}
- **请求体**: {packet_data.get('body', 'N/A')[:500]}{'...(截断)' if len(packet_data.get('body', '')) > 500 else ''}
- **查询参数**: {packet_data.get('query_params', {})}
- **POST参数**: {packet_data.get('post_params', {})}

### 2. 上下文行为特征
- **IP请求频率(5分钟)**: {context_features.get('ip_features', {}).get('request_frequency_5min', 0)} 次/分钟
- **访问的唯一URL数**: {context_features.get('ip_features', {}).get('unique_urls_accessed', 0)}
- **错误率(30分钟)**: {context_features.get('ip_features', {}).get('error_rate_30min', 0):.2%}
- **最近1分钟请求数**: {context_features.get('time_features', {}).get('requests_last_1min', 0)}
- **最近1小时请求数**: {context_features.get('time_features', {}).get('requests_last_1hour', 0)}
- **异常特征**: {context_features.get('anomaly_features', {})}
- **风险评分**: {context_features.get('risk_indicators', {}).get('risk_score', 0)}/100

### 3. 规则引擎检测结果
- **是否检测到攻击**: {rule_engine_result.get('is_attack', False)}
- **攻击类型**: {rule_engine_result.get('attack_types', [])}
- **风险等级**: {rule_engine_result.get('risk_level', 'N/A')}
- **置信度**: {rule_engine_result.get('confidence_score', 0):.2%}
- **匹配的攻击签名**: {[sig['name'] for sig in rule_engine_result.get('matched_signatures', [])]}
- **可疑特征**: {rule_engine_result.get('suspicious_features', [])}
- **检测证据**: {rule_engine_result.get('evidence', {})}

## 分析要求

请按照以下结构进行深度分析，确保分析的准确性和专业性：

### 1. 威胁概况评估
- 综合评估当前请求的威胁等级（无威胁/低风险/中风险/高风险/严重威胁）
- 说明威胁等级判定的主要依据
- 评估误报概率（0-100%）

### 2. 攻击向量分析
- 详细分析可能的攻击手法和技术路径
- 识别攻击者可能的目标和意图
- 分析攻击的复杂程度和技术水平

### 3. 影响评估
- 评估如果攻击成功可能造成的影响
- 分析可能受影响的系统组件和数据
- 评估业务连续性风险

### 4. 证据链分析
- 梳理支持威胁判定的关键证据
- 分析证据的可靠性和权重
- 识别可能的伪装或绕过技术

### 5. 防护建议
- 提供针对性的immediate响应措施（立即执行）
- 建议short-term防护加固措施（短期内实施）
- 推荐long-term安全改进措施（长期规划）

### 6. 监控建议
- 建议需要重点监控的指标和行为
- 提供后续跟踪分析的方向
- 建议威胁情报收集重点

## 分析原则

1. **客观性**: 基于数据事实进行分析，避免主观臆断
2. **全面性**: 综合考虑技术、行为、上下文等多维度信息
3. **实用性**: 提供可操作的建议和措施
4. **准确性**: 准确识别攻击类型和风险等级，避免误报漏报
5. **专业性**: 使用专业的网络安全术语和分析方法

## 特别注意

- 如果规则引擎已检测到明确攻击，重点分析攻击手法的精细特征
- 如果仅有异常特征但无明确攻击，重点分析是否存在新型或变形攻击
- 考虑攻击者可能的反检测技术和绕过手段
- 评估当前检测能力的局限性和改进空间

请开始你的专业分析："""

    return prompt


def get_false_positive_analysis_prompt(packet_data: dict, context_features: dict, rule_engine_result: dict) -> str:
    """
    生成误报分析的提示词，用于评估检测结果的准确性
    """
    
    prompt = f"""# 网络安全检测误报分析任务

你需要作为网络安全专家，专门分析当前的安全检测结果是否存在误报情况。

## 检测结果概况
- **检测结论**: {rule_engine_result.get('is_attack', False)}
- **攻击类型**: {rule_engine_result.get('attack_types', [])}
- **风险等级**: {rule_engine_result.get('risk_level', 'N/A')}
- **置信度**: {rule_engine_result.get('confidence_score', 0):.2%}

## 原始数据
### HTTP请求信息
- **URL**: {packet_data.get('url', 'N/A')}
- **方法**: {packet_data.get('method', 'N/A')}
- **User-Agent**: {packet_data.get('user_agent', 'N/A')}
- **请求体**: {packet_data.get('body', 'N/A')[:200]}

### 行为特征
- **请求频率**: {context_features.get('ip_features', {}).get('request_frequency_5min', 0)} 次/分钟
- **异常特征**: {context_features.get('anomaly_features', {})}

## 误报分析要求

请从以下角度分析是否存在误报：

### 1. 正常业务行为分析
- 该请求是否可能是正常的业务操作？
- 是否存在合理的业务场景解释？
- 用户行为模式是否符合正常使用习惯？

### 2. 技术实现合理性
- 检测到的"攻击特征"是否可能是正常的技术实现？
- 是否存在开发测试、自动化工具等合理解释？
- 编码或格式是否符合标准协议要求？

### 3. 上下文环境评估
- 请求来源和时间是否合理？
- 频率和模式是否在正常范围内？
- 是否存在环境因素导致的异常？

### 4. 检测规则准确性
- 触发的检测规则是否过于宽泛？
- 是否存在规则逻辑缺陷？
- 检测阈值是否合理？

## 输出要求

请提供：
1. **误报概率评估**: 0-100%的数值
2. **误报原因分析**: 如果可能是误报，详细说明原因
3. **建议措施**: 如何降低类似误报的发生

请开始分析："""

    return prompt


def get_attack_attribution_prompt(packet_data: dict, context_features: dict, rule_engine_result: dict) -> str:
    """
    生成攻击归因分析的提示词，用于分析攻击者特征和动机
    """
    
    prompt = f"""# 网络攻击归因分析任务

基于检测到的攻击行为，请进行攻击者特征画像和动机分析。

## 攻击概况
- **攻击类型**: {rule_engine_result.get('attack_types', [])}
- **风险等级**: {rule_engine_result.get('risk_level', 'N/A')}
- **攻击手法**: {[sig['name'] for sig in rule_engine_result.get('matched_signatures', [])]}

## 攻击数据
### 技术特征
- **攻击载荷**: {packet_data.get('body', 'N/A')[:300]}
- **工具特征**: {packet_data.get('user_agent', 'N/A')}
- **攻击路径**: {packet_data.get('url', 'N/A')}

### 行为特征
- **攻击频率**: {context_features.get('time_features', {}).get('requests_last_1min', 0)} 次/分钟
- **持续时间**: 基于上下文特征分析
- **攻击模式**: {context_features.get('risk_indicators', {}).get('risk_factors', [])}

## 归因分析要求

### 1. 攻击者技术水平评估
- 初学者/中级/高级/专业级
- 技术能力评估依据
- 使用的工具和技术复杂度

### 2. 攻击动机分析
- 经济利益/政治目的/个人恩怨/技术炫耀/随机攻击
- 目标选择的原因分析
- 攻击时机和方式的意图

### 3. 攻击者特征画像
- 可能的地理位置（基于技术特征）
- 活动时间模式
- 攻击习惯和偏好

### 4. 威胁等级评估
- 对组织的威胁程度
- 后续攻击的可能性
- 需要的防护重点

请提供详细的归因分析："""

    return prompt


# 工作流编排中LLM模块使用的主要提示词生成函数
def generate_llm_prompt(packet_data: str, context_features: str, rule_engine_result: str, analysis_type: str = "security_analysis") -> str:
    """
    为工作流编排中的LLM模块生成提示词
    
    Args:
        packet_data: 报文数据JSON字符串
        context_features: 上下文特征JSON字符串  
        rule_engine_result: 规则引擎结果JSON字符串
        analysis_type: 分析类型 ("security_analysis", "false_positive", "attribution")
        
    Returns:
        str: 格式化的提示词
    """
    import json
    
    try:
        packet_dict = json.loads(packet_data)
        context_dict = json.loads(context_features)
        rule_dict = json.loads(rule_engine_result)
        
        if analysis_type == "security_analysis":
            return get_security_analysis_prompt(packet_dict, context_dict, rule_dict)
        elif analysis_type == "false_positive":
            return get_false_positive_analysis_prompt(packet_dict, context_dict, rule_dict)
        elif analysis_type == "attribution":
            return get_attack_attribution_prompt(packet_dict, context_dict, rule_dict)
        else:
            return get_security_analysis_prompt(packet_dict, context_dict, rule_dict)
            
    except Exception as e:
        return f"提示词生成失败: {str(e)}"


# 示例使用
if __name__ == "__main__":
    # 测试用例
    sample_packet = {
        "packet_id": "PKT_1_1705392600",
        "url": "/admin/login.php?id=1' UNION SELECT user,pass FROM admin--",
        "method": "POST",
        "source_ip": "192.168.1.100",
        "user_agent": "sqlmap/1.6.12",
        "body": "username=admin&password=' OR '1'='1-- "
    }
    
    sample_context = {
        "ip_features": {"request_frequency_5min": 25, "error_rate_30min": 0.3},
        "risk_indicators": {"risk_score": 85}
    }
    
    sample_rule_result = {
        "is_attack": True,
        "attack_types": ["SQL注入"],
        "risk_level": "高风险",
        "confidence_score": 0.9,
        "matched_signatures": [{"name": "SQL注入-联合查询"}]
    }
    
    prompt = generate_llm_prompt(
        json.dumps(sample_packet),
        json.dumps(sample_context), 
        json.dumps(sample_rule_result)
    )
    
    print("LLM分析提示词示例:")
    print(prompt[:1000] + "...")  # 显示前1000个字符