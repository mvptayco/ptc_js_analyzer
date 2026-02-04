"""
Analysis Engine Models
"""
from dataclasses import dataclass
from typing import List, Dict, Any, Optional

@dataclass
class AnalysisResult:
    """Structure for analysis results"""
    url: str
    api_keys: List[Dict[str, Any]]
    credentials: List[Dict[str, Any]]
    emails: List[Dict[str, Any]]
    interesting_comments: List[Dict[str, Any]]
    xss_vulnerabilities: List[Dict[str, Any]]
    xss_functions: List[Dict[str, Any]]
    api_endpoints: List[Dict[str, Any]]
    parameters: List[Dict[str, Any]]
    paths_directories: List[Dict[str, Any]]
    errors: List[str]
    file_size: int
    analysis_timestamp: str
    server_info: Optional[Dict[str, Any]] = None
    csp_info: Optional[Dict[str, Any]] = None
    ip_address: Optional[str] = None
    cloudflare_analysis: Optional[Dict[str, Any]] = None
    rate_limit_info: Optional[Dict[str, Any]] = None
    recommendations: Optional[List[Dict[str, Any]]] = None
    skipped: bool = False
    relevance_score: float = 0.0
