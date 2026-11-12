"""Defensive heuristic detection engine for NetworkScope."""

from collections import defaultdict
import math
import re
from typing import List, Dict, Any, Tuple
from .models import PacketRecord, SecurityAlert, FlowSummary

CLEARTEXT_PORTS = {
    21: "FTP (unencrypted file transfer)",
    23: "Telnet (unencrypted remote shell)",
    80: "HTTP (unencrypted web traffic)",
    110: "POP3 (unencrypted email)",
    143: "IMAP (unencrypted email)",
}

HIGH_RISK_PORTS = {
    23: "Telnet",
    445: "SMB",
    3389: "RDP",
    4444: "Common reverse-shell / Metasploit default port",
    5900: "VNC",
}

SENSITIVE_PAYLOAD_PATTERNS = [
    re.compile(r"(password|passwd|pwd|secret|token|api_key|authorization:\s*basic)\s*[=:]", re.I),
]


def shannon_entropy(text: str) -> float:
    """Compute Shannon entropy in bits per character."""
    if not text:
        return 0.0
    freq: Dict[str, int] = defaultdict(int)
    for ch in text:
        freq[ch] += 1
    length = len(text)
    return -sum((count / length) * math.log2(count / length) for count in freq.values())


def analyze_packets(packets: List[PacketRecord]) -> Dict[str, Any]:
    """Run defensive heuristics, flow aggregation, and summary metrics over captured packets."""
    alerts: List[SecurityAlert] = []
    protocol_counts: Dict[str, int] = defaultdict(int)
    port_counts: Dict[int, int] = defaultdict(int)
    ip_bytes: Dict[str, int] = defaultdict(int)
    flows: Dict[str, FlowSummary] = {}

    # Trackers for anomaly heuristics
    src_to_dst_ports: Dict[Tuple[str, str], set] = defaultdict(set)
    src_syn_counts: Dict[Tuple[str, str], int] = defaultdict(int)
    src_synack_counts: Dict[Tuple[str, str], int] = defaultdict(int)
    cleartext_hits: Dict[Tuple[str, int], List[str]] = defaultdict(list)
    dns_anomalies: List[Tuple[PacketRecord, float, int]] = []
    high_risk_hits: Dict[Tuple[str, str, int], int] = defaultdict(int)

    total_bytes = 0

    for pkt in packets:
        total_bytes += pkt.length
        protocol_counts[pkt.protocol] += 1
        ip_bytes[pkt.src_ip] += pkt.length

        if pkt.dst_port is not None:
            port_counts[pkt.dst_port] += 1

        # Flow aggregation
        flow_key = f"{pkt.src_ip} -> {pkt.dst_ip} ({pkt.protocol})"
        if flow_key not in flows:
            flows[flow_key] = FlowSummary(
                flow_key=flow_key,
                src_ip=pkt.src_ip,
                dst_ip=pkt.dst_ip,
                protocol=pkt.protocol,
                packet_count=0,
                total_bytes=0,
                dst_ports=[],
                first_seen=pkt.timestamp,
                last_seen=pkt.timestamp,
            )
        fl = flows[flow_key]
        fl.packet_count += 1
        fl.total_bytes += pkt.length
        fl.last_seen = pkt.timestamp
        if pkt.dst_port is not None and pkt.dst_port not in fl.dst_ports:
            fl.dst_ports.append(pkt.dst_port)

        # Port scan & SYN flood tracking
        if pkt.protocol == "TCP" and pkt.dst_port is not None:
            src_to_dst_ports[(pkt.src_ip, pkt.dst_ip)].add(pkt.dst_port)
            flags = pkt.tcp_flags.upper()
            if "S" in flags and "A" not in flags:
                src_syn_counts[(pkt.src_ip, pkt.dst_ip)] += 1
            elif "S" in flags and "A" in flags:
                src_synack_counts[(pkt.dst_ip, pkt.src_ip)] += 1

        # Cleartext protocol & sensitive payload checks
        if pkt.dst_port in CLEARTEXT_PORTS:
            cleartext_hits[(pkt.src_ip, pkt.dst_port)].append(
                f"Pkt #{pkt.id} -> {pkt.dst_ip}:{pkt.dst_port}"
            )
        if pkt.payload_preview:
            for pattern in SENSITIVE_PAYLOAD_PATTERNS:
                if pattern.search(pkt.payload_preview):
                    alerts.append(
                        SecurityAlert(
                            id=f"ALR-CLR-{pkt.id}",
                            severity="HIGH",
                            category="Cleartext Credential Exposure",
                            title="Potential Sensitive Parameter in Unencrypted Payload",
                            description=(
                                f"Packet #{pkt.id} from {pkt.src_ip} to {pkt.dst_ip}:{pkt.dst_port} "
                                "contains credential-like key names in cleartext."
                            ),
                            source_ip=pkt.src_ip,
                            target_ip=pkt.dst_ip,
                            evidence=[f"Protocol: {pkt.protocol}", f"Preview: {pkt.payload_preview[:80]}"],
                            recommendation="Enforce TLS/HTTPS (port 443) or SSH and rotate any exposed test secrets.",
                            timestamp=pkt.timestamp,
                        )
                    )
                    break

        # High-risk port monitoring
        if pkt.dst_port in HIGH_RISK_PORTS:
            high_risk_hits[(pkt.src_ip, pkt.dst_ip, pkt.dst_port)] += 1

        # DNS tunneling / high-entropy label heuristic
        if pkt.dns_query:
            subdomain = pkt.dns_query.split(".")[0]
            ent = shannon_entropy(subdomain)
            if len(subdomain) >= 24 or ent >= 3.85:
                dns_anomalies.append((pkt, round(ent, 2), len(subdomain)))

    # Emit aggregated Port Scan alerts
    alert_idx = 1
    for (src_ip, dst_ip), ports in src_to_dst_ports.items():
        if len(ports) >= 8:
            sorted_ports = sorted(ports)
            alerts.append(
                SecurityAlert(
                    id=f"ALR-SCAN-{alert_idx}",
                    severity="HIGH",
                    category="Reconnaissance",
                    title=f"Multi-Port Sweep Detected ({len(ports)} distinct ports)",
                    description=(
                        f"{src_ip} probed {len(ports)} distinct destination ports on {dst_ip}, "
                        "matching horizontal/vertical port-scan reconnaissance."
                    ),
                    source_ip=src_ip,
                    target_ip=dst_ip,
                    evidence=[f"Ports sampled: {', '.join(map(str, sorted_ports[:12]))}"],
                    recommendation="Verify authorized vulnerability scanning; otherwise block source IP at host firewall and audit exposed services.",
                    timestamp=packets[-1].timestamp if packets else "",
                )
            )
            alert_idx += 1

    # Emit SYN burst alerts
    for (src_ip, dst_ip), syn_count in src_syn_counts.items():
        synack_count = src_synack_counts.get((src_ip, dst_ip), 0)
        if syn_count >= 12 and syn_count > (synack_count * 3 + 5):
            alerts.append(
                SecurityAlert(
                    id=f"ALR-SYN-{alert_idx}",
                    severity="MEDIUM",
                    category="Availability / Flood Heuristic",
                    title="Elevated Unanswered TCP SYN Burst",
                    description=(
                        f"{src_ip} sent {syn_count} TCP SYN packets to {dst_ip} with only "
                        f"{synack_count} SYN-ACK responses observed."
                    ),
                    source_ip=src_ip,
                    target_ip=dst_ip,
                    evidence=[f"SYN={syn_count}, SYN-ACK={synack_count}"],
                    recommendation="Enable SYN cookies, inspect rate limits, and verify upstream firewall filtering.",
                    timestamp=packets[-1].timestamp if packets else "",
                )
            )
            alert_idx += 1

    # Emit Cleartext Service alerts
    for (src_ip, port), refs in cleartext_hits.items():
        if len(refs) >= 1:
            alerts.append(
                SecurityAlert(
                    id=f"ALR-PORT-{alert_idx}",
                    severity="MEDIUM",
                    category="Insecure Transport",
                    title=f"Unencrypted Service Usage on Port {port}",
                    description=f"Observed {len(refs)} packet(s) from {src_ip} using {CLEARTEXT_PORTS[port]}.",
                    source_ip=src_ip,
                    target_ip=refs[0].split(" -> ")[-1].split(":")[0],
                    evidence=refs[:4],
                    recommendation="Migrate service to encrypted equivalent (HTTPS, SFTP, SSH).",
                    timestamp=packets[-1].timestamp if packets else "",
                )
            )
            alert_idx += 1

    # Emit High-Risk Port alerts
    for (src_ip, dst_ip, port), count in high_risk_hits.items():
        alerts.append(
            SecurityAlert(
                id=f"ALR-RISK-{alert_idx}",
                severity="MEDIUM" if port != 4444 else "HIGH",
                category="High-Risk Service Exposure",
                title=f"Traffic to Sensitive Port {port} ({HIGH_RISK_PORTS[port]})",
                description=f"Observed {count} packet(s) between {src_ip} and {dst_ip}:{port}.",
                source_ip=src_ip,
                target_ip=dst_ip,
                evidence=[f"Port {port}: {HIGH_RISK_PORTS[port]}", f"Packets: {count}"],
                recommendation="Confirm administrative necessity and restrict port access via VPN or allowlist.",
                timestamp=packets[-1].timestamp if packets else "",
            )
        )
        alert_idx += 1

    # Emit DNS Entropy alerts
    for pkt, ent, sub_len in dns_anomalies:
        alerts.append(
            SecurityAlert(
                id=f"ALR-DNS-{alert_idx}",
                severity="MEDIUM",
                category="DNS Anomaly",
                title="High-Entropy / Long Subdomain DNS Query",
                description=(
                    f"DNS query '{pkt.dns_query}' has subdomain length {sub_len} and "
                    f"Shannon entropy {ent} bits/char, which can indicate tunneling or DGA activity."
                ),
                source_ip=pkt.src_ip,
                target_ip=pkt.dst_ip,
                evidence=[f"Query: {pkt.dns_query}", f"Entropy: {ent}", f"Label length: {sub_len}"],
                recommendation="Inspect querying host process and check domain against DNS threat logs.",
                timestamp=pkt.timestamp,
            )
        )
        alert_idx += 1

    severity_rank = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}
    alerts.sort(key=lambda a: severity_rank.get(a.severity, 9))

    sorted_flows = sorted(flows.values(), key=lambda f: f.total_bytes, reverse=True)
    top_ports = sorted(port_counts.items(), key=lambda kv: kv[1], reverse=True)[:10]
    top_talkers = sorted(ip_bytes.items(), key=lambda kv: kv[1], reverse=True)[:8]

    return {
        "summary": {
            "total_packets": len(packets),
            "total_bytes": total_bytes,
            "unique_flows": len(flows),
            "alert_count": len(alerts),
            "high_severity_alerts": sum(1 for a in alerts if a.severity == "HIGH"),
            "medium_severity_alerts": sum(1 for a in alerts if a.severity == "MEDIUM"),
            "protocols": dict(protocol_counts),
            "top_ports": [{"port": p, "count": c} for p, c in top_ports],
            "top_talkers": [{"ip": ip, "bytes": b} for ip, b in top_talkers],
        },
        "alerts": [a.to_dict() for a in alerts],
        "flows": [f.to_dict() for f in sorted_flows],
        "packets": [p.to_dict() for p in packets],
    }
