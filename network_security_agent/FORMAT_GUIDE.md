# Python代码执行模块格式指南

## 🎯 正确的函数返回格式

所有Python代码执行模块都必须遵循以下标准格式：

### 函数模板
```python
def main(input_param1, input_param2):
    # 具体处理逻辑
    result_1 = ... # 处理后的结果变量1
    result_2 = ... # 处理后的结果变量2
    
    return {
        "output_1": result_1,
        "output_2": result_2
    }
```

### 关键要点
1. **入参**: 可以多个，直接作为函数参数
2. **出参**: 必须在同一个字典中返回，格式为 `{"key": value}`
3. **JSON序列化**: 复杂对象需要先用 `json.dumps()` 序列化为字符串

## 📦 各模块的具体格式

### 1. 单个报文提取模块 (BA)
- **文件**: `modules/message_extractor.py`
- **函数**: `main(user_input, current_index)`
- **返回**: 
```python
{
    "message_data": json.dumps(message_info)
}
```

### 2. 辅助决策信息提取模块 (BB)
- **文件**: `modules/context_extractor.py`
- **函数**: `main(message_data, messages_infos)`
- **返回**:
```python
{
    "messages_infos": json.dumps(updated_context)
}
```

### 3. 决策引擎模块 (BD)
- **文件**: `modules/decision_engine.py`
- **函数**: `main(message_data, messages_infos)`
- **返回**:
```python
{
    "decision_result": json.dumps(decision_data),
    "risk_score": risk_score,
    "attack_flag": attack_flag
}
```

### 4. LLM攻击分析模块 (BG)
- **文件**: `modules/llm_analyzer.py`
- **函数**: `main(message_data, messages_infos, decision_result)`
- **返回**:
```python
{
    "prompt": prompt_text,
    "llm_data": json.dumps(llm_metadata)
}
```

### 5. 响应生成器模块 (BF)
- **文件**: `modules/response_generator.py`
- **函数**: `main(decision_result, llm_result=None, original_decision=None)`
- **返回**:
```python
{
    "detect_result": json.dumps(final_result)
}
```

### 6. 全量结果更新模块 (BH)
- **文件**: `modules/result_updater.py`
- **函数**: `main(all_detect_results, detect_result, message_index)`
- **返回**:
```python
{
    "all_detect_results": json.dumps(updated_results_list),
    "current_result": json.dumps(current_result_data)
}
```

## 🔧 部署说明

### 在智能体平台上部署

1. **创建Python执行模块**
   - 复制各模块文件中的 `main` 函数代码
   - 确保函数名为 `main`
   - 保持参数名称和返回格式一致

2. **配置输入输出**
   - 输入: 直接映射函数参数
   - 输出: 使用返回字典中的键名

3. **数据流连接**
   ```
   message_extractor.message_data → context_extractor.message_data
   context_extractor.messages_infos → decision_engine.messages_infos
   decision_engine.decision_result → llm_analyzer.decision_result
   llm_analyzer.prompt → LLM模块.input
   decision_engine.decision_result → response_generator.decision_result
   response_generator.detect_result → result_updater.detect_result
   ```

## ✅ 测试验证

所有模块已通过格式测试，确保：
- ✅ 返回格式正确
- ✅ JSON序列化无误
- ✅ 数据类型匹配
- ✅ 参数传递正常

## 📝 示例

### 调用示例
```python
# 单个报文提取
result = main("GET /login HTTP/1.1\nPOST /api HTTP/1.1", "0")
# 返回: {"message_data": "{\"message\": \"GET /login HTTP/1.1\", \"index\": 0, ...}"}

# 辅助决策信息提取
result = main(message_data, "{}")
# 返回: {"messages_infos": "{...}"}

# 决策引擎
result = main(message_data, messages_infos)
# 返回: {"decision_result": "{...}", "risk_score": 85, "attack_flag": true}
```

## ⚠️ 注意事项

1. **JSON序列化**: 所有复杂对象必须序列化为字符串
2. **参数顺序**: 保持函数参数顺序与配置一致
3. **返回键名**: 返回字典的键名必须与后续模块的输入参数匹配
4. **错误处理**: 确保异常情况下也返回正确格式

这种格式完全符合智能体平台的要求，确保工作流能够正常运行！