"""NetworkScope CLI — Python Network Packet Analysis & Defensive Monitoring Suite."""

import argparse
import json
from pathlib import Path
import sys

from networkscope.detector import analyze_packets
from networkscope.server import packets_to_csv, run_dashboard
from networkscope.sniffer import (
    capture_live_packets,
    generate_demo_packets,
    load_pcap_packets,
)


def print_console_report(report: dict) -> None:
    s = report["summary"]
    print("=" * 72)
    print("  NETWORKSCOPE — DEFENSIVE PACKET ANALYSIS REPORT")
    print("=" * 72)
    print(f"  Packets Captured : {s['total_packets']}")
    print(f"  Total Bytes      : {s['total_bytes']} B")
    print(f"  Unique Flows     : {s['unique_flows']}")
    print(f"  Alerts Detected  : {s['alert_count']} (HIGH={s['high_severity_alerts']}, MEDIUM={s['medium_severity_alerts']})")
    print(f"  Protocols        : {s['protocols']}")
    print("-" * 72)
    if report["alerts"]:
        print("  DEFENSIVE ALERTS:")
        for a in report["alerts"]:
            print(f"   [{a['severity']}] {a['title']} ({a['source_ip']} -> {a['target_ip']})")
            print(f"       {a['description']}")
    else:
        print("  No heuristic alerts triggered.")
    print("-" * 72)
    for pkt in report["packets"][:15]:
        sport = f":{pkt['src_port']}" if pkt["src_port"] else ""
        dport = f":{pkt['dst_port']}" if pkt["dst_port"] else ""
        print(f"  #{pkt['id']:02d} [{pkt['protocol']:4s}] {pkt['src_ip']}{sport} -> {pkt['dst_ip']}{dport} | {pkt['length']}B | {pkt['info']}")
    if len(report["packets"]) > 15:
        print(f"  ... ({len(report['packets']) - 15} additional packets omitted in console summary)")
    print("=" * 72)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="NetworkScope: Defensive packet sniffer, PCAP analyzer, and web monitoring dashboard."
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--live", action="store_true", help="Capture live packets from network interface using Scapy")
    mode.add_argument("--pcap", type=str, help="Analyze an offline .pcap/.pcapng file")
    mode.add_argument("--demo", action="store_true", help="Run deterministic simulated traffic replay (no admin required)")

    parser.add_argument("--scenario", choices=["mixed", "recon", "cleartext", "dns_anomaly"], default="mixed",
                        help="Traffic scenario for --demo mode")
    parser.add_argument("--count", type=int, default=25, help="Packet count for --live capture")
    parser.add_argument("--iface", type=str, default=None, help="Network interface for --live capture")
    parser.add_argument("--filter", type=str, default="", help="BPF filter for --live capture (e.g., 'tcp port 443')")
    parser.add_argument("--dashboard", action="store_true", help="Launch interactive local web dashboard")
    parser.add_argument("--port", type=int, default=8765, help="Web dashboard HTTP port")
    parser.add_argument("--export-json", type=str, help="Write full analysis report to JSON file")
    parser.add_argument("--export-csv", type=str, help="Write captured packets to CSV file")

    args = parser.parse_args()

    try:
        if args.live:
            packets = capture_live_packets(count=args.count, iface=args.iface, bpf_filter=args.filter)
        elif args.pcap:
            packets = load_pcap_packets(args.pcap)
        else:
            packets = generate_demo_packets(scenario=args.scenario)
    except RuntimeError as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 1

    report = analyze_packets(packets)
    print_console_report(report)

    if args.export_json:
        Path(args.export_json).write_text(json.dumps(report, indent=2), encoding="utf-8")
        print(f"[+] JSON report saved to {args.export_json}")

    if args.export_csv:
        Path(args.export_csv).write_text(packets_to_csv(report["packets"]), encoding="utf-8")
        print(f"[+] CSV packets saved to {args.export_csv}")

    if args.dashboard:
        run_dashboard(report, port=args.port)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
