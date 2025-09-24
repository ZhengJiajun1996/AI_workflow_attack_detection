# 网络攻击检测工作流部署指南

本指南详细说明如何将网络攻击检测工作流部署到智能体平台上。

## 🎯 部署概述

本工作流专为智能体平台的循环体模块设计，完全解决了以下限制：
- ✅ 无法导入自定义包文件
- ✅ 无法保存中间数据到文件
- ✅ Python代码执行模块无法修改传入变量
- ✅ 需要通过循环变量更新模块实现变量传递

## 📋 部署前准备

### 1. 平台要求
- 支持循环体模块的智能体平台
- 支持Python代码执行模块
- 支持LLM模块调用
- 支持循环变量更新功能

### 2. 文件准备
确保以下文件已准备就绪：
```
network_security_agent/
├── workflow/workflow_config.json    # 工作流配置文件
├── test_example/test_workflow.py    # 测试示例
└── README.md                        # 项目文档
```

## 🚀 详细部署步骤

### 步骤1: 创建工作流

1. **登录智能体平台**
   - 进入工作流管理界面
   - 点击"新建工作流"

2. **导入工作流配置**
   - 选择"从JSON导入"
   - 上传 `workflow/workflow_config.json` 文件
   - 确认导入成功

3. **验证工作流结构**
   - 检查是否包含以下主要节点：
     - 开始节点A
     - 报文处理循环体B
     - 输出节点

### 步骤2: 配置循环体模块

1. **设置循环体参数**
   ```
   循环体ID: message_processing_loop
   最大迭代次数: 1000
   循环变量: ["messages_infos", "user_input", "all_detect_results"]
   迭代变量: current_message
   终止条件: all_messages_processed
   ```

2. **配置初始循环变量**
   ```json
   {
     "messages_infos": "{}",
     "user_input": "{{start_node.user_input}}",
     "all_detect_results": "[]"
   }
   ```

### 步骤3: 配置Python执行模块

#### 3.1 单个报文提取模块 (BA)
- **模块ID**: `message_extractor`
- **函数名**: `main`
- **输入参数**: `user_input`, `current_index`
- **代码**: 从workflow_config.json中复制对应的代码

```python
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
```

#### 3.2 辅助决策信息提取模块 (BB)
- **模块ID**: `context_extractor`
- **函数名**: `main`
- **输入参数**: `message`, `messages_infos`
- **代码**: 从workflow_config.json中复制对应的代码

#### 3.3 决策引擎 (BD)
- **模块ID**: `decision_engine`
- **函数名**: `main`
- **输入参数**: `message`, `messages_infos`
- **代码**: 从workflow_config.json中复制对应的代码

#### 3.4 LLM攻击分析模块 (BG)
- **模块ID**: `llm_analyzer`
- **函数名**: `main`
- **输入参数**: `message`, `messages_infos`, `decision_result`
- **代码**: 从workflow_config.json中复制对应的代码

#### 3.5 响应生成器 (BF)
- **模块ID**: `direct_response_generator`
- **函数名**: `main`
- **输入参数**: `decision_result`
- **代码**: 从workflow_config.json中复制对应的代码

#### 3.6 全量结果更新模块 (BH)
- **模块ID**: `result_updater`
- **函数名**: `main`
- **输入参数**: `all_detect_results`, `detect_result`, `message_index`
- **代码**: 从workflow_config.json中复制对应的代码

### 步骤4: 配置LLM模块

1. **LLM分析模块配置**
   ```json
   {
     "id": "llm_analysis",
     "type": "llm_module",
     "model": "gpt-4",
     "temperature": 0.1,
     "max_tokens": 1500,
     "system_prompt": "你是一位资深的网络安全专家，专门负责深度分析网络攻击和威胁。请基于提供的数据进行专业、准确的安全分析，并以JSON格式返回结果。"
   }
   ```

2. **输入配置**
   - 输入来源: `{{llm_analyzer.output.prompt}}`
   - 条件: `{{risk_switch.output}} == 'llm_analysis'`

### 步骤5: 配置分支判断模块

1. **风险评分判断模块 (BE)**
   ```json
   {
     "id": "risk_switch",
     "type": "switch_case",
     "condition_field": "risk_score",
     "cases": [
       {
         "condition": "<= 50",
         "next_node": "direct_response_generator"
       },
       {
         "condition": "> 50",
         "next_node": "llm_analysis"
       }
     ],
     "default_case": "direct_response_generator"
   }
   ```

### 步骤6: 配置循环变量更新模块

1. **辅助决策信息更新 (BC)**
   ```json
   {
     "id": "context_updater",
     "type": "loop_variable_update",
     "update_variable": "messages_infos",
     "update_source": "{{context_extractor.output}}"
   }
   ```

2. **检测结果更新 (BI)**
   ```json
   {
     "id": "loop_variable_update",
     "type": "loop_variable_update",
     "update_variable": "all_detect_results",
     "update_source": "{{result_updater.output}}"
   }
   ```

## 🔧 配置验证

### 1. 工作流结构验证
确保工作流包含以下节点和连接：
```
开始节点A → 报文处理循环体B → 输出节点
                ↓
         ┌─ 循环子图 ─┐
         │ BA → BB → BC → BD → BE │
         │    ↙    ↘              │
         │ BF      BG → LLM       │
         │    ↘    ↙              │
         │ BH → BI                │
         └────────────────────────┘
```

### 2. 输入输出验证
- **输入**: `user_input` (字符串类型)
- **输出**: `all_detect_results` (数组类型)

### 3. 循环变量验证
确保循环体中正确维护以下变量：
- `messages_infos`: 辅助决策信息
- `user_input`: 原始输入报文
- `all_detect_results`: 累积检测结果

## 🧪 测试部署

### 1. 单元测试
使用提供的测试脚本验证各模块功能：
```bash
python3 test_example/test_workflow.py
```

### 2. 集成测试
在智能体平台上进行端到端测试：

**测试输入**:
```json
{
  "user_input": "GET /login.php HTTP/1.1\\nSELECT * FROM users WHERE id=1\\n<script>alert('xss')</script>"
}
```

**期望输出**:
```json
[
  {
    "message_index": 0,
    "attack_flag": false,
    "attack_type": "none",
    "risk_score": 15,
    "detection_method": "rule_engine"
  },
  {
    "message_index": 1,
    "attack_flag": true,
    "attack_type": "sql_injection",
    "risk_score": 85,
    "detection_method": "llm_enhanced"
  },
  {
    "message_index": 2,
    "attack_flag": true,
    "attack_type": "xss",
    "risk_score": 75,
    "detection_method": "llm_enhanced"
  }
]
```

### 3. 性能测试
- 测试不同报文数量的处理性能
- 验证循环体迭代限制
- 检查内存使用情况

## 📊 监控配置

### 1. 关键指标监控
```json
{
  "metrics": [
    "total_processing_time",
    "messages_processed",
    "attack_detection_rate",
    "llm_analysis_rate"
  ]
}
```

### 2. 告警配置
```json
{
  "alerts": [
    {
      "condition": "attack_detection_rate > 20%",
      "action": "high_priority_alert"
    },
    {
      "condition": "processing_time > 300s",
      "action": "performance_alert"
    }
  ]
}
```

## 🚨 故障排除

### 常见问题

1. **循环体无法启动**
   - 检查循环变量配置
   - 验证迭代源设置
   - 确认终止条件

2. **Python模块执行失败**
   - 检查代码语法
   - 验证输入参数
   - 查看错误日志

3. **LLM调用失败**
   - 检查API密钥配置
   - 验证模型可用性
   - 确认输入格式

4. **变量更新失败**
   - 检查循环变量更新模块配置
   - 验证更新源数据格式
   - 确认变量名称匹配

### 调试技巧

1. **启用详细日志**
   ```json
   {
     "logging_level": "DEBUG"
   }
   ```

2. **添加调试输出**
   在Python模块中添加调试信息：
   ```python
   print(f"Debug: Processing message {message}")
   ```

3. **分步测试**
   逐个测试各个模块的功能

## 📈 性能优化

### 1. 循环体优化
- 设置合适的最大迭代次数
- 优化循环变量数据结构
- 减少不必要的计算

### 2. LLM调用优化
- 合理设置温度参数
- 控制最大token数
- 批量处理相似请求

### 3. 内存管理
- 定期清理历史数据
- 限制统计信息大小
- 优化数据结构

## 🔄 维护更新

### 1. 规则更新
定期更新攻击检测规则：
- 修改决策引擎中的正则表达式
- 添加新的攻击模式
- 调整风险评分算法

### 2. 模型更新
- 更新LLM模型版本
- 优化提示词模板
- 调整分析参数

### 3. 配置调优
- 根据实际使用情况调整参数
- 优化性能设置
- 更新监控指标

## 📞 技术支持

如果在部署过程中遇到问题，请：

1. 查看详细的错误日志
2. 参考测试示例进行验证
3. 检查平台文档和限制
4. 联系技术支持团队

## ✅ 部署检查清单

- [ ] 工作流配置导入成功
- [ ] 循环体模块配置正确
- [ ] 所有Python模块部署完成
- [ ] LLM模块配置验证
- [ ] 分支判断逻辑正确
- [ ] 循环变量更新功能正常
- [ ] 输入输出格式验证
- [ ] 单元测试通过
- [ ] 集成测试通过
- [ ] 性能测试满足要求
- [ ] 监控配置完成
- [ ] 告警规则设置
- [ ] 文档更新完成

完成以上所有步骤后，网络攻击检测工作流即可投入使用！