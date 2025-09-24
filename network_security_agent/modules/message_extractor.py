"""
单个报文提取模块 (BA)
功能：从user_input中提取单个报文
输入：user_input (文本), current_index (索引)
输出：单个报文信息 (JSON格式)
"""

def main(user_input, iteration_index):
    import json
    import re
    
    try:
        # 解析当前迭代次数
        index = int(iteration_index) if str(iteration_index).isdigit() else 0
        
        # 将输入文本按HTTP请求边界分割：空行(两个或以上换行)作为分隔符
        # 支持CRLF/ LF 以及多余空白行
        parts = re.split(r"\r?\n\r?\n+", user_input.strip()) if user_input else []
        # 清理首尾空白，过滤空片段
        messages = [p.strip() for p in parts if p and p.strip()]
        
        if index < len(messages):
            message = messages[index]
            message_data = {
                'message': message,
                'iteration_index': index,
                'total_count': len(messages),
                'completed': False
            }
        else:
            message_data = {
                'message': '',
                'iteration_index': index,
                'total_count': len(messages),
                'completed': True
            }
        
        return {
            "message_data": json.dumps(message_data)
        }
    except Exception as e:
        error_data = {
            'error': True,
            'message': str(e)
        }
        return {
            "message_data": json.dumps(error_data)
        }