# 独立模块版本 - 工作流编排专用

## 概述

这个目录包含了网络安全检测智能体的独立版本模块，专门为Agent平台的工作流编排设计。每个模块都是自包含的，无需外部依赖，可以直接在Python代码执行模块中使用。

## 解决的问题

在Agent平台的工作流编排中，Python代码执行模块通常面临以下限制：
1. **无文件系统架构** - 无法访问项目文件结构
2. **无法导入自定义包** - 不能使用相对导入或自定义模块
3. **运行环境隔离** - 每个模块独立运行，无法共享状态
4. **依赖限制** - 只能使用标准库或预安装的包

## 解决方案

### 1. 代码内嵌策略
将所有依赖的工具函数、数据结构和逻辑直接内嵌到每个模块文件中：

```python
def execute_module_function(input_data: str) -> str:
    # 内嵌的工具函数
    def helper_function():
        pass
    
    # 内嵌的数据结构
    class InlineDataClass:
        pass
    
    # 主处理逻辑
    try:
        # 处理逻辑
        pass
    except Exception as e:
        # 错误处理
        pass
```

### 2. 状态管理策略
对于需要跨请求保持状态的数据（如IP统计），使用以下方法：

#### 方法A：全局变量（适用于单实例）
```python
# 全局变量存储统计数据
_ip_stats = defaultdict(lambda: {...})
_url_stats = defaultdict(lambda: {...})
```

#### 方法B：外部存储（推荐用于生产环境）
```python
# 可以集成Redis、数据库等外部存储
def get_ip_stats(ip):
    # 从外部存储获取
    pass

def update_ip_stats(ip, data):
    # 更新到外部存储
    pass
```

### 3. 数据传递策略
所有模块间的数据传递都通过JSON字符串进行：

```python
def execute_module(input_json: str) -> str:
    # 解析输入
    input_data = json.loads(input_json)
    
    # 处理逻辑
    result = process_data(input_data)
    
    # 返回JSON字符串
    return json.dumps(result, ensure_ascii=False)
```

## 模块说明

### 1. packet_input_standalone.py
**报文输入模块**
- 功能：解析HTTP报文，提取基础信息和可疑模式
- 输入：原始报文JSON字符串
- 输出：标准化的报文数据JSON字符串
- 特点：内嵌报文解析器和验证逻辑

### 2. context_extraction_standalone.py
**上下文特征提取模块**
- 功能：提取IP行为、时间模式、异常特征等
- 输入：报文输入模块的输出
- 输出：上下文特征数据JSON字符串
- 特点：内嵌统计数据管理和特征计算逻辑

### 3. rule_engine_standalone.py
**规则引擎扫描模块**
- 功能：基于专家规则检测各种攻击类型
- 输入：报文数据 + 上下文特征数据
- 输出：检测结果JSON字符串
- 特点：内嵌100+检测规则和风险评估逻辑

### 4. llm_prompt_generator_standalone.py
**LLM提示词生成模块**
- 功能：为LLM分析生成专业提示词
- 输入：报文数据 + 上下文特征 + 规则引擎结果
- 输出：格式化的提示词字符串
- 特点：内嵌多种分析类型的提示词模板

### 5. response_generator_standalone.py
**安全响应生成模块**
- 功能：生成最终的安全响应和防护建议
- 输入：LLM分析 + 报文数据 + 上下文特征 + 规则结果
- 输出：完整的安全响应报告JSON字符串
- 特点：内嵌威胁等级判断和建议生成逻辑

## 工作流配置示例

### Agent平台配置

```json
{
  "workflow": {
    "nodes": [
      {
        "id": "packet_input",
        "type": "python_execution",
        "code": "从 packet_input_standalone.py 复制代码",
        "function": "execute_packet_input",
        "input": "{{workflow.input}}"
      },
      {
        "id": "context_extraction",
        "type": "python_execution", 
        "code": "从 context_extraction_standalone.py 复制代码",
        "function": "execute_context_feature_extraction",
        "input": "{{packet_input.output}}"
      },
      {
        "id": "rule_engine",
        "type": "python_execution",
        "code": "从 rule_engine_standalone.py 复制代码",
        "function": "execute_rule_engine_scan",
        "inputs": {
          "packet_data": "{{packet_input.output}}",
          "context_features": "{{context_extraction.output}}"
        }
      },
      {
        "id": "risk_decision",
        "type": "switch_case",
        "condition": "{{rule_engine.output.risk_level}}",
        "cases": [
          {"value": "严重", "next": "llm_prompt"},
          {"value": "高风险", "next": "llm_prompt"},
          {"value": "中风险", "next": "suspicious_check"},
          {"value": "低风险", "next": "safe_output"}
        ]
      },
      {
        "id": "llm_prompt",
        "type": "python_execution",
        "code": "从 llm_prompt_generator_standalone.py 复制代码",
        "function": "generate_llm_prompt",
        "inputs": {
          "packet_data": "{{packet_input.output}}",
          "context_features": "{{context_extraction.output}}",
          "rule_engine_result": "{{rule_engine.output}}"
        }
      },
      {
        "id": "llm_analysis",
        "type": "llm_module",
        "model": "gpt-4",
        "prompt": "{{llm_prompt.output}}",
        "temperature": 0.1
      },
      {
        "id": "response_generator",
        "type": "python_execution",
        "code": "从 response_generator_standalone.py 复制代码",
        "function": "generate_security_response",
        "inputs": {
          "llm_analysis": "{{llm_analysis.output}}",
          "packet_data": "{{packet_input.output}}",
          "context_data": "{{context_extraction.output}}",
          "rule_result": "{{rule_engine.output}}"
        }
      }
    ]
  }
}
```

## 部署步骤

### 1. 准备代码
将每个独立模块的代码复制到Agent平台的Python代码执行模块中。

### 2. 配置工作流
按照上述配置示例设置工作流节点和连接关系。

### 3. 测试验证
使用提供的测试用例验证每个模块的功能。

### 4. 生产部署
根据实际需求调整参数和阈值。

## 性能优化建议

### 1. 状态存储优化
对于高并发场景，建议使用外部存储：
```python
import redis
r = redis.Redis(host='localhost', port=6379, db=0)

def get_ip_stats(ip):
    data = r.get(f"ip_stats:{ip}")
    return json.loads(data) if data else default_stats()
```

### 2. 内存管理
定期清理过期数据：
```python
def cleanup_expired_data():
    current_time = time.time()
    cutoff_time = current_time - 3600  # 1小时
    # 清理逻辑
```

### 3. 缓存优化
对频繁使用的数据进行缓存：
```python
from functools import lru_cache

@lru_cache(maxsize=1000)
def get_attack_rules():
    # 缓存攻击规则
    return rules
```

## 故障排除

### 常见问题

1. **JSON解析错误**
   - 检查输入数据格式
   - 确保所有字符串都是有效的JSON

2. **内存不足**
   - 实施数据清理机制
   - 使用外部存储

3. **处理超时**
   - 优化算法复杂度
   - 减少不必要的计算

4. **状态丢失**
   - 使用持久化存储
   - 实施状态恢复机制

### 调试技巧

1. **日志记录**
```python
import logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def execute_function(data):
    logger.info(f"Processing data: {data[:100]}...")
    # 处理逻辑
```

2. **错误处理**
```python
try:
    result = process_data(input_data)
except Exception as e:
    logger.error(f"Processing failed: {str(e)}")
    return error_response(str(e))
```

## 扩展指南

### 添加新的检测规则
在规则引擎模块中添加新规则：
```python
def get_attack_rules():
    rules = {
        'new_attack_type': [
            {
                'name': "新攻击类型",
                'pattern': r"attack_pattern",
                'description': "检测描述",
                'risk_level': "高风险"
            }
        ]
    }
    return rules
```

### 集成新的LLM模型
修改提示词生成器以适配不同模型：
```python
def generate_model_specific_prompt(model_type, data):
    if model_type == "claude":
        return claude_prompt_format(data)
    elif model_type == "gpt":
        return gpt_prompt_format(data)
```

这些独立模块版本确保了在各种Agent平台上的兼容性和可用性，同时保持了原有系统的完整功能。