"""
网络安全检测智能体 - 数据结构定义
"""
from dataclasses import dataclass, field
from typing import Dict, List, Any, Optional
from datetime import datetime
from enum import Enum


class AttackType(Enum):
    """攻击类型枚举"""
    SQL_INJECTION = "SQL注入"
    XSS = "跨站脚本攻击"
    CSRF = "跨站请求伪造"
    DDOS = "分布式拒绝服务攻击"
    BRUTE_FORCE = "暴力破解"
    DIRECTORY_TRAVERSAL = "目录遍历"
    COMMAND_INJECTION = "命令注入"
    XXE = "XML外部实体注入"
    SSRF = "服务端请求伪造"
    DESERIALIZATION = "反序列化攻击"
    BUFFER_OVERFLOW = "缓冲区溢出"
    WEB_SHELL = "Web Shell上传"
    SCANNER_PROBE = "扫描器探测"
    SUSPICIOUS_FREQUENCY = "可疑频次访问"
    MALICIOUS_USER_AGENT = "恶意User-Agent"
    UNKNOWN = "未知攻击"


class RiskLevel(Enum):
    """风险等级"""
    LOW = "低风险"
    MEDIUM = "中风险"
    HIGH = "高风险"
    CRITICAL = "严重"


@dataclass
class HttpPacket:
    """HTTP报文数据结构"""
    timestamp: datetime
    source_ip: str
    destination_ip: str
    source_port: int
    destination_port: int
    method: str
    url: str
    headers: Dict[str, str]
    body: str
    user_agent: str
    referer: Optional[str] = None
    cookies: Dict[str, str] = field(default_factory=dict)
    query_params: Dict[str, str] = field(default_factory=dict)
    post_params: Dict[str, str] = field(default_factory=dict)


@dataclass
class ContextFeatures:
    """上下文特征数据结构"""
    # IP相关统计
    ip_request_count: int = 0
    ip_request_frequency: float = 0.0
    ip_unique_urls: int = 0
    ip_error_rate: float = 0.0
    
    # URL相关统计
    url_request_count: int = 0
    url_parameter_count: int = 0
    url_suspicious_patterns: List[str] = field(default_factory=list)
    
    # 时间窗口统计
    requests_last_minute: int = 0
    requests_last_5_minutes: int = 0
    requests_last_hour: int = 0
    
    # 异常特征
    unusual_headers: List[str] = field(default_factory=list)
    large_payload_size: bool = False
    suspicious_encoding: bool = False
    
    # 会话特征
    session_duration: float = 0.0
    session_request_count: int = 0


@dataclass
class AttackSignature:
    """攻击特征签名"""
    name: str
    attack_type: AttackType
    pattern: str
    description: str
    risk_level: RiskLevel
    confidence: float = 0.0


@dataclass
class DetectionResult:
    """检测结果数据结构"""
    is_attack: bool
    attack_types: List[AttackType] = field(default_factory=list)
    risk_level: RiskLevel = RiskLevel.LOW
    confidence_score: float = 0.0
    matched_signatures: List[AttackSignature] = field(default_factory=list)
    suspicious_features: List[str] = field(default_factory=list)
    evidence: Dict[str, Any] = field(default_factory=dict)
    recommendations: List[str] = field(default_factory=list)


@dataclass
class LLMAnalysisResult:
    """LLM分析结果"""
    analysis_summary: str
    detailed_analysis: str
    attack_vector: str
    impact_assessment: str
    recommended_actions: List[str]
    confidence_level: float
    false_positive_probability: float