"""Packet capture, PCAP loading, and deterministic traffic replay for NetworkScope."""

from datetime import datetime, timedelta, timezone
import ipaddress
import random
from typing import Any, List, Optional
from .models import PacketRecord

PROTO_MAP = {1: "ICMP", 6: "TCP", 17: "UDP"}


def _is_private_ip(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def _direction(src_ip: str, dst_ip: str) -> str:
    src_priv = _is_private_ip(src_ip)
    dst_priv = _is_private_ip(dst_ip)
    if src_priv and not dst_priv:
        return "outbound"
    if not src_priv and dst_priv:
        return "inbound"
    return "internal"


def _format_tcp_flags(flags_val: Any) -> str:
    return str(flags_val) if flags_val is not None else ""


def convert_scapy_packets(raw_packets: List[Any]) -> List[PacketRecord]:
    """Convert Scapy packet objects into normalized PacketRecord instances."""
    from scapy.all import IP, TCP, UDP, ICMP, DNS, DNSQR, Raw  # type: ignore

    records: List[PacketRecord] = []
    for idx, pkt in enumerate(raw_packets, start=1):
        if not pkt.haslayer(IP):
            continue
        ip_layer = pkt[IP]
        src_ip = str(ip_layer.src)
        dst_ip = str(ip_layer.dst)
        proto_num = int(ip_layer.proto)
        proto = PROTO_MAP.get(proto_num, f"PROTO-{proto_num}")
        src_port: Optional[int] = None
        dst_port: Optional[int] = None
        tcp_flags = ""
        dns_query: Optional[str] = None
        info_parts: List[str] = []

        if pkt.haslayer(TCP):
            tcp = pkt[TCP]
            proto = "TCP"
            src_port = int(tcp.sport)
            dst_port = int(tcp.dport)
            tcp_flags = _format_tcp_flags(tcp.flags)
            info_parts.append(f"{src_port} -> {dst_port} [{tcp_flags}]")
        elif pkt.haslayer(UDP):
            udp = pkt[UDP]
            proto = "UDP"
            src_port = int(udp.sport)
            dst_port = int(udp.dport)
            info_parts.append(f"{src_port} -> {dst_port}")
        elif pkt.haslayer(ICMP):
            icmp = pkt[ICMP]
            proto = "ICMP"
            info_parts.append(f"type={icmp.type} code={icmp.code}")

        if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
            proto = "DNS"
            qname = pkt[DNSQR].qname
            if isinstance(qname, bytes):
                dns_query = qname.decode("utf-8", errors="ignore").rstrip(".")
            else:
                dns_query = str(qname).rstrip(".")
            info_parts.append(f"Query {dns_query}")

        payload_preview = ""
        if pkt.haslayer(Raw):
            raw_bytes = bytes(pkt[Raw].load)[:120]
            printable = "".join(chr(b) if 32 <= b <= 126 else "." for b in raw_bytes)
            payload_preview = printable

        ts = datetime.fromtimestamp(float(pkt.time), tz=timezone.utc).isoformat()
        records.append(
            PacketRecord(
                id=idx,
                timestamp=ts,
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                protocol=proto,
                length=len(pkt),
                tcp_flags=tcp_flags,
                info=" | ".join(info_parts) or proto,
                dns_query=dns_query,
                payload_preview=payload_preview,
                direction=_direction(src_ip, dst_ip),
            )
        )
    return records


def capture_live_packets(count: int = 25, iface: Optional[str] = None, bpf_filter: str = "") -> List[PacketRecord]:
    """Capture live packets via Scapy. Raises RuntimeError with clear guidance if unavailable."""
    try:
        from scapy.all import sniff  # type: ignore
    except ImportError as exc:
        raise RuntimeError(
            "Scapy is not installed. Run `pip install -r requirements.txt` or use `--demo` mode."
        ) from exc

    try:
        kwargs = {"count": count, "store": True}
        if iface:
            kwargs["iface"] = iface
        if bpf_filter:
            kwargs["filter"] = bpf_filter
        raw = sniff(**kwargs)
    except Exception as exc:
        raise RuntimeError(
            f"Live capture failed ({exc}). Ensure Npcap (Windows) or root/CAP_NET_RAW privileges (Linux/macOS) are available, or run `--demo` / `--pcap` mode."
        ) from exc

    return convert_scapy_packets(list(raw))


def load_pcap_packets(pcap_path: str) -> List[PacketRecord]:
    """Load packets from an offline .pcap/.pcapng file via Scapy."""
    try:
        from scapy.all import rdpcap  # type: ignore
    except ImportError as exc:
        raise RuntimeError("Scapy is required to parse .pcap files (`pip install scapy`).") from exc

    raw = rdpcap(pcap_path)
    return convert_scapy_packets(list(raw))


def generate_demo_packets(scenario: str = "mixed", seed: int = 42) -> List[PacketRecord]:
    """Generate deterministic realistic packet traces for defensive testing without live NIC privileges."""
    rng = random.Random(seed)
    base_time = datetime(2026, 11, 12, 16, 30, 0, tzinfo=timezone.utc)
    records: List[PacketRecord] = []
    pkt_id = 1

    def add_pkt(offset_ms: int, src: str, dst: str, sport: Optional[int], dport: Optional[int],
                proto: str, length: int, flags: str = "", info: str = "",
                dns_query: Optional[str] = None, payload: str = "") -> None:
        nonlocal pkt_id
        ts = (base_time + timedelta(milliseconds=offset_ms)).isoformat()
        records.append(
            PacketRecord(
                id=pkt_id,
                timestamp=ts,
                src_ip=src,
                dst_ip=dst,
                src_port=sport,
                dst_port=dport,
                protocol=proto,
                length=length,
                tcp_flags=flags,
                info=info,
                dns_query=dns_query,
                payload_preview=payload,
                direction=_direction(src, dst),
            )
        )
        pkt_id += 1

    # Baseline HTTPS, DNS, and ICMP traffic
    normal_domains = [
        "api.github.com",
        "cdn.jsdelivr.net",
        "registry.npmjs.org",
        "fonts.googleapis.com",
        "pypi.org",
    ]
    t = 0
    for dom in normal_domains:
        t += rng.randint(40, 120)
        add_pkt(t, "192.168.10.24", "1.1.1.1", rng.randint(49152, 60000), 53, "DNS", 74,
                info=f"Standard query A {dom}", dns_query=dom)
        t += 18
        add_pkt(t, "1.1.1.1", "192.168.10.24", 53, rng.randint(49152, 60000), "DNS", 98,
                info=f"Standard query response A {dom}")
        t += 25
        dst_ip = f"140.82.113.{rng.randint(3, 18)}"
        sport = rng.randint(50000, 61000)
        add_pkt(t, "192.168.10.24", dst_ip, sport, 443, "TCP", 66, "S", f"{sport} -> 443 [SYN]")
        add_pkt(t + 12, dst_ip, "192.168.10.24", 443, sport, "TCP", 66, "SA", f"443 -> {sport} [SYN, ACK]")
        add_pkt(t + 16, "192.168.10.24", dst_ip, sport, 443, "TCP", 54, "A", f"{sport} -> 443 [ACK]")
        add_pkt(t + 28, "192.168.10.24", dst_ip, sport, 443, "TCP", rng.randint(420, 1460), "PA", "TLSv1.3 Application Data")
        add_pkt(t + 44, dst_ip, "192.168.10.24", 443, sport, "TCP", rng.randint(680, 1480), "PA", "TLSv1.3 Application Data")

    add_pkt(t + 60, "192.168.10.24", "192.168.10.1", None, None, "ICMP", 74, info="Echo (ping) request seq=1")
    add_pkt(t + 64, "192.168.10.1", "192.168.10.24", None, None, "ICMP", 74, info="Echo (ping) reply seq=1")

    if scenario in ("mixed", "recon"):
        # Simulated reconnaissance port sweep + unanswered SYN burst
        scan_ports = [21, 22, 23, 25, 53, 80, 110, 139, 443, 445, 3306, 3389, 5432, 8080]
        for idx, port in enumerate(scan_ports):
            t += 15
            add_pkt(t, "203.0.113.45", "192.168.10.10", 41200 + idx, port, "TCP", 60, "S",
                    f"{41200 + idx} -> {port} [SYN]")

    if scenario in ("mixed", "cleartext"):
        # Simulated legacy cleartext HTTP login warning
        t += 120
        add_pkt(
            t,
            "192.168.10.31",
            "198.51.100.72",
            53104,
            80,
            "TCP",
            312,
            "PA",
            "POST /login HTTP/1.1",
            payload="POST /login HTTP/1.1 Host: legacy.internal username=demo&password=sample_redacted",
        )

    if scenario in ("mixed", "dns_anomaly"):
        # Simulated high-entropy subdomain DNS query
        t += 90
        add_pkt(
            t,
            "192.168.10.42",
            "8.8.8.8",
            58812,
            53,
            "DNS",
            128,
            info="Standard query TXT 9f4c2a8b7e1d60c3a4f9e2b1d8a7c5e3.telemetry-check.example",
            dns_query="9f4c2a8b7e1d60c3a4f9e2b1d8a7c5e3.telemetry-check.example",
        )

    return records
