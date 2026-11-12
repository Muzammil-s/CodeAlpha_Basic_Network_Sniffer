"""Data models for NetworkScope packet inspection and defensive alerts."""

from dataclasses import dataclass, field, asdict
from typing import List, Dict, Any, Optional


@dataclass
class PacketRecord:
    id: int
    timestamp: str
    src_ip: str
    dst_ip: str
    src_port: Optional[int]
    dst_port: Optional[int]
    protocol: str
    length: int
    tcp_flags: str = ""
    info: str = ""
    dns_query: Optional[str] = None
    payload_preview: str = ""
    direction: str = "outbound"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class SecurityAlert:
    id: str
    severity: str  # "HIGH" | "MEDIUM" | "LOW" | "INFO"
    category: str
    title: str
    description: str
    source_ip: str
    target_ip: str
    evidence: List[str] = field(default_factory=list)
    recommendation: str = ""
    timestamp: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class FlowSummary:
    flow_key: str
    src_ip: str
    dst_ip: str
    protocol: str
    packet_count: int
    total_bytes: int
    dst_ports: List[int] = field(default_factory=list)
    first_seen: str = ""
    last_seen: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
