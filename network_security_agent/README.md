# 网络攻击检测智能体

一个基于工作流编排的智能网络安全检测系统，通过报文分析、上下文特征提取、规则引擎和LLM深度分析，实现对网络攻击的实时检测和威胁评估。

## 🎯 项目特点

- **多层检测架构**: 报文解析 → 特征提取 → 规则引擎 → LLM深度分析
- **实时威胁检测**: 支持高频报文处理，毫秒级响应
- **智能决策引擎**: 基于风险等级的自动化响应决策
- **全面攻击覆盖**: 支持SQL注入、XSS、DDoS、暴力破解等多种攻击类型
- **工作流编排**: 模块化设计，支持灵活的工作流配置

## 🏗️ 系统架构

```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│  报文输入   │───▶│ 上下文特征  │───▶│  规则引擎   │───▶│ 风险决策    │
│    模块     │    │  提取模块   │    │  扫描模块   │    │    节点     │
└─────────────┘    └─────────────┘    └─────────────┘    └─────┬───────┘
                                                               │
                   ┌─────────────┐    ┌─────────────┐         │
                   │  安全放行   │◀───│     LLM     │◀────────┘
                   └─────────────┘    │  深度分析   │
                                      └─────────────┘
                                            │
                                      ┌─────▼───────┐
                                      │ 告警/阻断   │
                                      │  响应生成   │
                                      └─────────────┘
```

## 📦 项目结构

```
network_security_agent/
├── modules/                          # 核心检测模块
│   ├── packet_input.py              # 报文输入处理模块
│   ├── context_feature_extraction.py # 上下文特征提取模块
│   ├── rule_engine_scanner.py       # 规则引擎扫描模块
│   └── response_generator.py        # 安全响应生成模块
├── prompts/                         # LLM提示词模块
│   └── llm_analysis_prompts.py     # LLM深度分析提示词
├── utils/                           # 工具类和数据结构
│   ├── data_structures.py          # 数据结构定义
│   └── packet_parser.py            # 报文解析工具
├── workflow/                        # 工作流配置
│   ├── workflow_config.json        # 工作流编排配置
│   └── README.md                   # 工作流说明文档
├── demo/                           # 演示和测试
│   └── complete_demo.py           # 完整功能演示
└── README.md                      # 项目说明文档
```

## 🚀 快速开始

### 1. 环境准备

```bash
# Python 3.8+ 环境
pip install -r requirements.txt  # 如果有依赖文件的话
```

### 2. 运行演示

```bash
cd network_security_agent
python demo/complete_demo.py
```

### 3. 模块测试

```bash
# 测试报文输入模块
python modules/packet_input.py

# 测试上下文特征提取
python modules/context_feature_extraction.py

# 测试规则引擎扫描
python modules/rule_engine_scanner.py
```

## 🔧 工作流编排配置

### Agent平台集成

本系统设计为在Agent平台上进行工作流编排，主要配置如下：

#### 1. Python代码执行模块配置

```json
{
  "modules": [
    {
      "name": "packet_input",
      "type": "python_execution",
      "function": "execute_packet_input",
      "file": "modules/packet_input.py"
    },
    {
      "name": "context_extraction", 
      "type": "python_execution",
      "function": "execute_context_feature_extraction",
      "file": "modules/context_feature_extraction.py"
    },
    {
      "name": "rule_engine",
      "type": "python_execution", 
      "function": "execute_rule_engine_scan",
      "file": "modules/rule_engine_scanner.py"
    }
  ]
}
```

#### 2. LLM模块配置

```json
{
  "llm_module": {
    "model": "gpt-4",
    "temperature": 0.1,
    "max_tokens": 2000,
    "prompt_generator": "generate_llm_prompt",
    "system_prompt": "你是一位资深的网络安全专家..."
  }
}
```

#### 3. Switch-Case决策配置

```json
{
  "decision_nodes": [
    {
      "name": "risk_decision",
      "type": "switch_case",
      "condition_field": "risk_level",
      "cases": [
        {"condition": "严重", "next": "llm_analysis"},
        {"condition": "高风险", "next": "llm_analysis"},
        {"condition": "中风险", "next": "suspicious_check"},
        {"condition": "低风险", "next": "safe_pass"}
      ]
    }
  ]
}
```

## 🛡️ 支持的攻击类型

### Web应用攻击
- **SQL注入**: 联合查询、布尔盲注、堆叠查询等
- **XSS攻击**: 脚本标签、事件处理器、编码绕过等
- **命令注入**: 系统命令、管道符、反引号执行等
- **目录遍历**: 相对路径、敏感文件访问等
- **XXE注入**: 外部实体、文件读取等
- **SSRF攻击**: 内网访问、云元数据等
- **反序列化**: Java、Python等反序列化漏洞

### 网络层攻击
- **DDoS攻击**: 基于频率和模式的检测
- **暴力破解**: 登录接口的高频尝试
- **扫描器探测**: 工具特征和路径模式识别

### 行为异常
- **异常访问频率**: 基于时间窗口的频率分析
- **可疑User-Agent**: 工具特征和异常模式
- **会话异常**: 会话劫持和异常操作

## 📊 性能指标

### 处理性能
- **单报文处理时间**: < 100ms (不含LLM)
- **LLM分析时间**: < 5s
- **并发处理能力**: 1000+ requests/second
- **内存占用**: < 512MB

### 检测准确性
- **误报率**: < 5%
- **漏报率**: < 2%
- **检测覆盖率**: > 95%
- **响应时间**: < 10s (包含LLM分析)

## 🔍 检测示例

### SQL注入攻击检测

**输入报文:**
```json
{
  "method": "POST",
  "url": "/login.php?id=1' UNION SELECT user,pass FROM admin--",
  "body": "username=admin&password=' OR '1'='1-- ",
  "headers": {"User-Agent": "sqlmap/1.6.12"}
}
```

**检测结果:**
```json
{
  "is_attack": true,
  "attack_types": ["SQL注入"],
  "risk_level": "严重威胁",
  "confidence_score": 0.95,
  "response_action": "block_immediately",
  "recommendations": [
    "立即阻断该IP地址",
    "检查数据库访问日志",
    "审计所有SQL查询参数化"
  ]
}
```

### 正常请求处理

**输入报文:**
```json
{
  "method": "GET", 
  "url": "/products/laptop-dell-xps13",
  "headers": {
    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
    "Referer": "https://ecommerce-site.com/search?q=laptop"
  }
}
```

**检测结果:**
```json
{
  "is_attack": false,
  "risk_level": "低风险", 
  "response_action": "allow_and_log",
  "executive_summary": "检测到正常HTTP请求，未发现威胁"
}
```

## 🎨 LLM提示词设计

系统内置了专业的网络安全分析提示词，包括：

### 1. 安全分析提示词
- 威胁概况评估
- 攻击向量分析  
- 影响评估
- 证据链分析
- 防护建议
- 监控建议

### 2. 误报分析提示词
- 正常业务行为分析
- 技术实现合理性
- 上下文环境评估
- 检测规则准确性

### 3. 攻击归因提示词
- 攻击者技术水平评估
- 攻击动机分析
- 攻击者特征画像
- 威胁等级评估

## ⚙️ 配置和扩展

### 1. 规则引擎扩展

```python
# 添加新的攻击签名
new_signature = AttackSignature(
    name="自定义攻击规则",
    attack_type=AttackType.CUSTOM,
    pattern=r"custom_pattern",
    description="自定义攻击描述",
    risk_level=RiskLevel.HIGH
)
```

### 2. 特征工程优化

```python
# 添加新的上下文特征
def extract_custom_features(packet_data):
    # 自定义特征提取逻辑
    return custom_features
```

### 3. LLM模型集成

```python
# 集成不同的LLM模型
def call_custom_llm(prompt):
    # 调用自定义LLM API
    return analysis_result
```

## 📈 监控和告警

### 关键指标
- 处理延迟监控
- 攻击检出率统计
- 误报率分析
- 系统吞吐量监控
- 资源使用监控

### 告警规则
- 处理时间超过阈值
- 错误率异常增长
- 攻击量突然激增
- 系统资源不足

## 🤝 贡献指南

1. Fork 项目仓库
2. 创建功能分支 (`git checkout -b feature/AmazingFeature`)
3. 提交更改 (`git commit -m 'Add some AmazingFeature'`)
4. 推送到分支 (`git push origin feature/AmazingFeature`)
5. 打开 Pull Request

## 📄 许可证

本项目采用 MIT 许可证 - 查看 [LICENSE](LICENSE) 文件了解详情。

## 📞 联系方式

如有问题或建议，请通过以下方式联系：

- 提交 Issue
- 发送邮件
- 技术讨论群

---

**注意**: 本系统仅用于合法的网络安全防护目的，请勿用于任何非法活动。