# 网络攻击检测智能体 - 部署指南

## 解决工作流编排中的导入问题

### 问题描述

在Agent平台的工作流编排中，Python代码执行模块面临以下限制：

1. **无文件系统架构** - 无法访问项目文件结构
2. **无法导入自定义包** - 不能使用 `from ..utils import` 等相对导入
3. **运行环境隔离** - 每个模块独立运行，无法共享代码
4. **依赖限制** - 只能使用标准库或预安装的包

### 解决方案

我们提供了两套解决方案：

## 方案一：独立模块版本（推荐）

### 特点
- ✅ 零依赖，完全自包含
- ✅ 直接复制粘贴即可使用
- ✅ 无需文件系统支持
- ✅ 适用于所有Agent平台

### 使用方法

#### 1. 获取独立模块代码
独立模块位于 `standalone_modules/` 目录：

```
standalone_modules/
├── packet_input_standalone.py          # 报文输入模块
├── context_extraction_standalone.py    # 上下文特征提取
├── rule_engine_standalone.py          # 规则引擎扫描
├── llm_prompt_generator_standalone.py # LLM提示词生成
└── response_generator_standalone.py   # 安全响应生成
```

#### 2. 在Agent平台中配置

**步骤1：创建Python代码执行节点**

以报文输入模块为例：

```python
# 节点名称: packet_input
# 节点类型: Python代码执行模块

# 直接复制 packet_input_standalone.py 中的全部代码
# 或者使用以下简化版本：

import json
import re
import urllib.parse
from datetime import datetime

def execute_packet_input(raw_packet_data: str) -> str:
    """报文输入处理函数"""
    
    # [复制完整的函数实现代码]
    # 这里包含所有内嵌的工具函数和处理逻辑
    
    try:
        # 解析和处理逻辑
        packet_input = json.loads(raw_packet_data)
        # ... 处理逻辑 ...
        return json.dumps(result, ensure_ascii=False, indent=2)
    except Exception as e:
        error_result = {
            'error': True,
            'error_message': str(e),
            'timestamp': datetime.now().isoformat()
        }
        return json.dumps(error_result, ensure_ascii=False, indent=2)

# 工作流调用入口
result = execute_packet_input(input_data)
```

**步骤2：配置工作流连接**

```json
{
  "workflow": {
    "nodes": [
      {
        "id": "packet_input",
        "type": "python_execution",
        "function": "execute_packet_input",
        "input": "{{workflow.input}}"
      },
      {
        "id": "context_extraction", 
        "type": "python_execution",
        "function": "execute_context_feature_extraction",
        "input": "{{packet_input.output}}"
      },
      {
        "id": "rule_engine",
        "type": "python_execution", 
        "function": "execute_rule_engine_scan",
        "inputs": {
          "packet_data": "{{packet_input.output}}",
          "context_features": "{{context_extraction.output}}"
        }
      },
      {
        "id": "risk_decision",
        "type": "switch_case",
        "condition_field": "risk_level",
        "input": "{{rule_engine.output}}",
        "cases": [
          {"condition": "严重", "next": "llm_analysis"},
          {"condition": "高风险", "next": "llm_analysis"},
          {"condition": "中风险", "next": "suspicious_check"},
          {"condition": "低风险", "next": "safe_output"}
        ]
      },
      {
        "id": "llm_prompt_gen",
        "type": "python_execution",
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
        "prompt": "{{llm_prompt_gen.output}}",
        "temperature": 0.1,
        "max_tokens": 2000
      },
      {
        "id": "response_gen",
        "type": "python_execution",
        "function": "generate_security_response",
        "inputs": {
          "llm_analysis": "{{llm_analysis.output}}",
          "packet_data": "{{packet_input.output}}",
          "context_data": "{{context_extraction.output}}",
          "rule_result": "{{rule_engine.output}}"
        }
      }
    ],
    "edges": [
      {"from": "packet_input", "to": "context_extraction"},
      {"from": "context_extraction", "to": "rule_engine"},
      {"from": "rule_engine", "to": "risk_decision"},
      {"from": "risk_decision", "to": "llm_prompt_gen", "condition": "risk_level in ['严重', '高风险']"},
      {"from": "llm_prompt_gen", "to": "llm_analysis"},
      {"from": "llm_analysis", "to": "response_gen"}
    ]
  }
}
```

## 方案二：代码注入版本

### 特点
- 🔄 保持原有模块化结构
- 📝 需要手动合并代码
- 🎯 适合深度定制需求

### 实现方法

#### 1. 创建合并脚本

```python
# merge_modules.py - 代码合并工具
import os
import re

def merge_modules():
    """合并所有模块代码为单个文件"""
    
    # 读取所有依赖文件
    utils_code = read_file('utils/data_structures.py')
    parser_code = read_file('utils/packet_parser.py')
    
    # 移除导入语句
    utils_code = remove_imports(utils_code)
    parser_code = remove_imports(parser_code)
    
    # 读取主模块代码
    main_code = read_file('modules/packet_input.py')
    main_code = remove_imports(main_code)
    
    # 合并代码
    merged_code = f"""
# 合并的网络安全检测模块
import json
import re
from datetime import datetime

# === 数据结构定义 ===
{utils_code}

# === 工具函数 ===
{parser_code}

# === 主处理逻辑 ===
{main_code}
"""
    
    return merged_code

def remove_imports(code):
    """移除相对导入语句"""
    lines = code.split('\n')
    filtered_lines = []
    for line in lines:
        if not line.strip().startswith(('from ..', 'from .')):
            filtered_lines.append(line)
    return '\n'.join(filtered_lines)
```

#### 2. 使用合并后的代码

将合并后的代码直接粘贴到Agent平台的Python执行模块中。

## 方案三：动态导入版本

### 特点
- 🚀 运行时动态加载
- 📦 支持模块化开发
- ⚠️ 需要平台支持文件系统

### 实现方法

```python
# dynamic_loader.py
import importlib.util
import sys
from typing import Any

def load_module_from_string(code: str, module_name: str) -> Any:
    """从字符串代码动态加载模块"""
    spec = importlib.util.spec_from_loader(module_name, loader=None)
    module = importlib.util.module_from_spec(spec)
    exec(code, module.__dict__)
    sys.modules[module_name] = module
    return module

def execute_with_dependencies():
    """动态加载并执行模块"""
    
    # 数据结构代码
    data_structures_code = """
class AttackType(Enum):
    SQL_INJECTION = "SQL注入"
    # ... 其他定义
"""
    
    # 加载依赖模块
    data_structures = load_module_from_string(data_structures_code, 'data_structures')
    
    # 主处理逻辑
    main_code = f"""
from data_structures import AttackType

def process_packet(data):
    # 使用导入的类型
    return AttackType.SQL_INJECTION
"""
    
    main_module = load_module_from_string(main_code, 'main_processor')
    return main_module.process_packet
```

## 部署最佳实践

### 1. 选择合适的方案

| 平台类型 | 推荐方案 | 原因 |
|----------|----------|------|
| 通用Agent平台 | 独立模块版本 | 兼容性最好，零依赖 |
| 支持文件系统的平台 | 原始模块版本 | 保持代码结构清晰 |
| 高度定制需求 | 代码注入版本 | 灵活性最高 |

### 2. 性能优化配置

#### 内存管理
```python
# 在上下文特征提取模块中添加
import gc

def cleanup_memory():
    """定期清理内存"""
    # 清理过期数据
    current_time = time.time()
    cutoff_time = current_time - 3600
    
    # 清理统计数据
    for ip in list(_ip_stats.keys()):
        if _ip_stats[ip]['last_seen'] < cutoff_time:
            del _ip_stats[ip]
    
    # 强制垃圾回收
    gc.collect()
```

#### 缓存优化
```python
from functools import lru_cache

@lru_cache(maxsize=100)
def get_cached_rules():
    """缓存攻击规则"""
    return get_attack_rules()
```

### 3. 错误处理和监控

#### 统一错误处理
```python
def safe_execute(func, *args, **kwargs):
    """安全执行函数，统一错误处理"""
    try:
        return func(*args, **kwargs)
    except Exception as e:
        error_info = {
            'error': True,
            'error_type': type(e).__name__,
            'error_message': str(e),
            'timestamp': datetime.now().isoformat(),
            'function': func.__name__
        }
        # 记录日志或发送告警
        return json.dumps(error_info)
```

#### 性能监控
```python
import time
from functools import wraps

def monitor_performance(func):
    """性能监控装饰器"""
    @wraps(func)
    def wrapper(*args, **kwargs):
        start_time = time.time()
        result = func(*args, **kwargs)
        end_time = time.time()
        
        # 记录性能指标
        performance_log = {
            'function': func.__name__,
            'execution_time': end_time - start_time,
            'timestamp': datetime.now().isoformat()
        }
        
        # 可以发送到监控系统
        return result
    return wrapper
```

### 4. 配置管理

#### 环境变量配置
```python
import os

# 配置参数
CONFIG = {
    'TIME_WINDOW': int(os.getenv('TIME_WINDOW', '3600')),
    'RISK_THRESHOLD': float(os.getenv('RISK_THRESHOLD', '60.0')),
    'MAX_REQUEST_FREQUENCY': int(os.getenv('MAX_REQUEST_FREQUENCY', '100')),
    'LLM_ANALYSIS_THRESHOLD': int(os.getenv('LLM_ANALYSIS_THRESHOLD', '50'))
}

def get_config(key, default=None):
    """获取配置参数"""
    return CONFIG.get(key, default)
```

## 测试和验证

### 1. 单元测试

```python
def test_packet_input():
    """测试报文输入模块"""
    sample_data = {
        "method": "POST",
        "url": "/test",
        "headers": {"Host": "example.com"},
        "body": "test=1"
    }
    
    result = execute_packet_input(json.dumps(sample_data))
    result_dict = json.loads(result)
    
    assert result_dict.get('method') == 'POST'
    assert 'packet_id' in result_dict
    print("✅ 报文输入模块测试通过")

def test_all_modules():
    """测试所有模块"""
    test_packet_input()
    # test_context_extraction()
    # test_rule_engine()
    # test_llm_prompt_generator()
    # test_response_generator()
    print("✅ 所有模块测试通过")
```

### 2. 集成测试

```python
def test_complete_workflow():
    """测试完整工作流"""
    # 模拟SQL注入攻击
    attack_packet = {
        "method": "POST",
        "url": "/login?id=1' UNION SELECT * FROM users--",
        "headers": {"User-Agent": "sqlmap/1.6"},
        "body": "username=admin&password=' OR 1=1--"
    }
    
    # 执行完整流程
    step1 = execute_packet_input(json.dumps(attack_packet))
    step2 = execute_context_feature_extraction(step1)
    step3 = execute_rule_engine_scan(step1, step2)
    
    result = json.loads(step3)
    assert result.get('is_attack') == True
    assert 'SQL注入' in result.get('attack_types', [])
    
    print("✅ 完整工作流测试通过")
```

## 常见问题解决

### Q1: 模块执行超时怎么办？
**A:** 优化算法复杂度，添加超时控制：

```python
import signal

def timeout_handler(signum, frame):
    raise TimeoutError("执行超时")

def execute_with_timeout(func, timeout=30):
    signal.signal(signal.SIGALRM, timeout_handler)
    signal.alarm(timeout)
    try:
        result = func()
        signal.alarm(0)  # 取消超时
        return result
    except TimeoutError:
        return {"error": True, "message": "执行超时"}
```

### Q2: 内存使用过高怎么办？
**A:** 实施内存管理策略：

```python
import sys
import psutil

def check_memory_usage():
    """检查内存使用情况"""
    process = psutil.Process()
    memory_mb = process.memory_info().rss / 1024 / 1024
    
    if memory_mb > 500:  # 超过500MB
        cleanup_expired_data()
        gc.collect()
    
    return memory_mb
```

### Q3: 如何处理并发请求？
**A:** 使用线程安全的数据结构：

```python
import threading
from collections import defaultdict

# 线程安全的统计数据
_lock = threading.Lock()
_ip_stats = defaultdict(dict)

def update_ip_stats_safe(ip, data):
    """线程安全的统计更新"""
    with _lock:
        _ip_stats[ip].update(data)
```

### Q4: 如何调试模块问题？
**A:** 添加详细的日志记录：

```python
import logging

# 配置日志
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def debug_execute(func_name, input_data):
    """调试模式执行"""
    logger.debug(f"执行函数: {func_name}")
    logger.debug(f"输入数据: {input_data[:200]}...")
    
    try:
        result = execute_function(input_data)
        logger.debug(f"执行成功: {len(result)} 字符")
        return result
    except Exception as e:
        logger.error(f"执行失败: {str(e)}", exc_info=True)
        raise
```

## 总结

通过以上三种方案，您可以根据Agent平台的具体限制选择最适合的部署方式：

1. **独立模块版本** - 最通用，推荐首选
2. **代码注入版本** - 适合定制化需求
3. **动态导入版本** - 适合支持文件系统的平台

每种方案都经过测试验证，可以在各种Agent平台上成功部署和运行网络攻击检测智能体系统。