# 网络攻击检测工作流

基于用户需求的智能网络攻击检测系统，通过循环体架构实现报文批量处理和上下文状态保持。

## 🎯 系统特点

- **精确流程**: 严格按照用户需求的流程设计
- **循环体架构**: 基于智能体平台的循环体模块
- **上下文保持**: 维护辅助决策变量和统计信息
- **智能决策**: 基于风险评分的自适应LLM分析
- **无依赖**: 所有代码内嵌，无需外部包文件

## 🏗️ 工作流程

```
开始节点A: 用户传入请求报文文本(user_input)
    ↓
循环体B: 处理每个报文，维护辅助决策变量
    ├─ BA: 单个报文提取模块
    ├─ BB: 辅助决策信息提取模块  
    ├─ BC: 循环变量更新模块
    ├─ BD: 决策引擎
    ├─ BE: 风险评分判断(≤50直接输出，>50进入LLM)
    ├─ BF: 响应生成器(直接输出分支)
    ├─ BG: LLM攻击分析模块
    ├─ BH: 全量结果更新模块
    └─ BI: 循环变量更新模块
    ↓
输出全部响应结果(all_detect_results)
```

## 📦 项目结构

```
network_security_agent/
├── workflow/
│   └── workflow_config.json          # 工作流配置文件
├── test_example/
│   └── test_workflow.py             # 完整测试示例
├── README.md                        # 项目说明
└── requirements.txt                 # 依赖文件
```

## 🚀 核心模块

### 1. 单个报文提取模块 (BA)
- **功能**: 从user_input中提取单个报文
- **输入**: user_input(文本), current_index(索引)
- **输出**: 单个报文信息(JSON格式)
- **特点**: 按行分割报文，支持索引访问

### 2. 辅助决策信息提取模块 (BB)
- **功能**: 提取和更新辅助决策信息
- **输入**: message(当前报文), messages_infos(历史信息)
- **输出**: 更新后的辅助决策信息
- **特点**: 统计攻击模式、消息长度、处理历史

### 3. 决策引擎 (BD)
- **功能**: 基于报文和上下文进行攻击检测
- **输入**: message(报文), messages_infos(辅助决策信息)
- **输出**: 攻击标志、类型、风险评分、评估信息
- **特点**: 支持SQL注入、XSS、命令注入、路径遍历检测

### 4. LLM攻击分析模块 (BG)
- **功能**: 为高风险报文生成LLM分析提示词
- **输入**: message, messages_infos, decision_result
- **输出**: LLM分析提示词和相关元数据
- **特点**: 智能提示词生成，上下文感知分析

### 5. 响应生成器 (BF)
- **功能**: 生成最终的安全响应报告
- **输入**: decision_result(决策结果)
- **输出**: 完整的检测结果和建议
- **特点**: 自适应建议生成，置信度评估

### 6. 全量结果更新模块 (BH)
- **功能**: 将研判结果更新至返回变量
- **输入**: all_detect_results, detect_result, message_index
- **输出**: 更新后的结果列表
- **特点**: 累积结果管理，索引维护

## 🔧 技术实现

### 解决的核心问题
1. ✅ **无法导入自定义包** - 所有依赖代码内嵌到模块中
2. ✅ **无法保存中间数据** - 通过循环变量实现状态保持
3. ✅ **Python代码执行限制** - 通过循环变量更新模块实现变量修改
4. ✅ **标准函数格式** - 所有模块使用标准main()函数

### 关键技术特性
- **上下文状态管理**: 通过messages_infos维护统计信息
- **循环变量更新**: 使用专门的更新模块实现变量传递
- **智能风险评分**: 基于多维度特征的评分算法
- **自适应分析**: 根据风险评分自动选择检测路径

## 📊 支持的攻击类型

### Web应用攻击
- **SQL注入**: union select、布尔盲注、堆叠查询
- **XSS攻击**: 脚本标签、事件处理器、JavaScript协议
- **命令注入**: 系统命令、管道符、反引号执行
- **目录遍历**: 相对路径、敏感文件访问

### 检测特征
- **报文长度分析**: 异常长度检测
- **特殊字符统计**: 危险字符密度分析
- **模式匹配**: 正则表达式攻击模式识别
- **上下文关联**: 基于历史行为的关联分析

## 🎨 工作流配置

### 循环体配置
```json
{
  "id": "message_processing_loop",
  "type": "loop_module",
  "loop_config": {
    "max_iterations": 1000,
    "loop_variables": ["messages_infos", "user_input", "all_detect_results"],
    "iteration_variable": "current_message",
    "termination_condition": "all_messages_processed"
  }
}
```

### 风险评分判断
```json
{
  "id": "risk_switch",
  "type": "switch_case",
  "condition_field": "risk_score",
  "cases": [
    {"condition": "<= 50", "next_node": "direct_response_generator"},
    {"condition": "> 50", "next_node": "llm_analysis"}
  ]
}
```

## 🚀 快速开始

### 1. 测试系统功能
```bash
cd network_security_agent
python3 test_example/test_workflow.py
```

### 2. 部署到智能体平台

#### 步骤1: 导入工作流配置
1. 将 `workflow/workflow_config.json` 导入到智能体平台
2. 创建工作流实例

#### 步骤2: 配置Python执行模块
将工作流配置中的代码复制到对应的Python执行模块中：

```python
# 单个报文提取模块
def main(user_input, current_index):
    # 复制配置中的完整代码
    # ... 实现代码 ...
    return {"output": json.dumps(result)}
```

#### 步骤3: 配置LLM模块
```json
{
  "type": "llm_module",
  "model": "gpt-4",
  "temperature": 0.1,
  "max_tokens": 1500,
  "input": "{{llm_analyzer.output.prompt}}"
}
```

### 3. 输入数据格式
```json
{
  "user_input": "GET /login.php HTTP/1.1\\nSELECT * FROM users\\n<script>alert('xss')</script>"
}
```

## 📈 输出结果格式

### 单个检测结果
```json
{
  "message_index": 0,
  "timestamp": "2024-01-15T10:30:00Z",
  "attack_flag": true,
  "attack_type": "sql_injection",
  "risk_score": 85,
  "risk_assessment": "Risk level: high, Score: 85. Factors: ['Detected attacks: ['sql_injection']']",
  "detection_method": "llm_enhanced",
  "confidence": 0.9,
  "recommendations": ["立即阻断此请求", "记录攻击日志"]
}
```

### 完整输出结果
```json
[
  {
    "message_index": 0,
    "attack_flag": false,
    "attack_type": "none",
    "risk_score": 15,
    "detection_method": "rule_engine",
    "confidence": 0.6
  },
  {
    "message_index": 1,
    "attack_flag": true,
    "attack_type": "sql_injection",
    "risk_score": 85,
    "detection_method": "llm_enhanced",
    "confidence": 0.9
  }
]
```

## 🔍 示例输出

### 测试运行结果
```
=== 网络攻击检测工作流完整测试 ===

输入报文:
0: GET /login.php HTTP/1.1
1: POST /api/users HTTP/1.1
2: SELECT * FROM users WHERE id=1 OR 1=1
3: <script>alert('xss')</script>
4: ../../../etc/passwd

开始处理 5 个报文...

--- 处理报文 1/5 ---
报文: GET /login.php HTTP/1.1
检测结果:
  攻击标志: False
  攻击类型: none
  风险评分: 15
  检测方法: rule_engine

--- 处理报文 2/5 ---
报文: SELECT * FROM users WHERE id=1 OR 1=1
检测结果:
  攻击标志: True
  攻击类型: sql_injection
  风险评分: 85
  检测方法: llm_enhanced

=== 最终处理报告 ===
总报文数: 5
攻击报文数: 3
攻击率: 60.0%

攻击类型分布:
  sql_injection: 1
  xss: 1
  path_traversal: 1

所有检测结果:
  [0] ✅ 正常 - none (评分: 15)
  [1] ✅ 正常 - none (评分: 20)
  [2] 🚨 攻击 - sql_injection (评分: 85)
  [3] 🚨 攻击 - xss (评分: 75)
  [4] 🚨 攻击 - path_traversal (评分: 65)
```

## 🛠️ 扩展和定制

### 添加新的攻击检测规则
在决策引擎模块的attack_patterns中添加新的正则表达式：

```python
attack_patterns['new_attack_type'] = [
    r'new_pattern_1',
    r'new_pattern_2'
]
```

### 自定义风险评分规则
在决策引擎模块的评分逻辑中添加新的评分因子：

```python
# 基于自定义条件的评分
if custom_condition:
    risk_score += 20
    risk_factors.append('custom_risk_factor')
```

### 扩展LLM分析类型
在LLM分析模块中添加新的提示词模板：

```python
def generate_custom_prompt(message, context, decision):
    return f"自定义分析提示词: {message}"
```

## 📋 部署检查清单

- [ ] 确认智能体平台支持循环体模块
- [ ] 配置循环变量和迭代源
- [ ] 部署所有Python执行模块
- [ ] 配置LLM模型和API密钥
- [ ] 设置监控和告警规则
- [ ] 进行功能测试和性能测试
- [ ] 配置日志记录和错误处理

## ⚠️ 注意事项

1. **内存管理**: 定期清理过期的统计数据，避免内存泄漏
2. **性能优化**: 对于大量报文，考虑分批处理
3. **错误处理**: 确保单个报文处理失败不影响整个循环
4. **状态一致性**: 确保循环变量更新的原子性
5. **LLM调用**: 合理控制LLM调用频率，避免超限

## 🎯 项目优势

- **完全符合需求**: 严格按照用户描述的流程实现
- **无外部依赖**: 所有代码内嵌，无需额外包文件
- **状态保持**: 通过循环变量实现上下文状态管理
- **智能决策**: 结合规则引擎和LLM的混合检测架构
- **易于部署**: 标准化的模块格式，便于平台集成
- **可扩展性**: 模块化设计支持灵活的功能扩展

这个工作流完全按照您的要求实现，解决了所有技术限制，提供了一个高效、智能、可扩展的网络攻击检测解决方案！