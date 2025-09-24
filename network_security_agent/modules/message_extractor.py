"""
单个报文提取模块 (BA)
功能：从user_input中提取单个报文
输入：user_input (文本), current_index (索引)
输出：单个报文信息 (JSON格式)
"""

def main(user_input, current_index):
    import json
    import re
    
    try:
        # 解析当前索引
        index = int(current_index) if current_index.isdigit() else 0
        
        # 将输入文本按行分割，每行作为一个报文
        messages = [line.strip() for line in user_input.split('\n') if line.strip()]
        
        if index < len(messages):
            message = messages[index]
            message_data = {
                'message': message,
                'index': index,
                'total_count': len(messages),
                'completed': False
            }
        else:
            message_data = {
                'message': '',
                'index': index,
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