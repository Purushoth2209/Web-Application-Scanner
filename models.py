# models.py

from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional

@dataclass
class Vulnerability:
    url: str
    field: str
    payload: str
    detection_method: str
    screenshot_path: Optional[str] = None # To store path to screenshot if available

@dataclass
class ScanReport:
    target_url: str
    start_time: str
    end_time: str
    visited_urls: List[str]
    potential_vulnerabilities: List[Vulnerability]
    summary: Dict[str, Any] = field(default_factory=dict)