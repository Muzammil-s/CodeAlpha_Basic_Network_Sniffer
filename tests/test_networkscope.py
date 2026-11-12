import unittest

from networkscope.detector import analyze_packets, shannon_entropy
from networkscope.models import PacketRecord
from networkscope.server import packets_to_csv
from networkscope.sniffer import generate_demo_packets


class NetworkScopeTests(unittest.TestCase):
    def test_shannon_entropy(self):
        self.assertEqual(shannon_entropy(""), 0.0)
        self.assertLess(shannon_entropy("aaaaaaaaaa"), 0.1)
        self.assertGreater(shannon_entropy("9f4c2a8b7e1d60c3a4f9e2b1d8a7c5e3"), 3.5)

    def test_mixed_demo_detects_expected_alerts(self):
        packets = generate_demo_packets(scenario="mixed", seed=42)
        report = analyze_packets(packets)
        summary = report["summary"]
        self.assertGreater(summary["total_packets"], 20)
        self.assertGreaterEqual(summary["alert_count"], 3)
        categories = {a["category"] for a in report["alerts"]}
        self.assertIn("Reconnaissance", categories)
        self.assertIn("Cleartext Credential Exposure", categories)
        self.assertIn("DNS Anomaly", categories)

    def test_port_scan_threshold(self):
        pkts = [
            PacketRecord(
                id=i + 1,
                timestamp="2026-11-12T12:00:00+00:00",
                src_ip="203.0.113.99",
                dst_ip="192.168.1.5",
                src_port=40000 + i,
                dst_port=p,
                protocol="TCP",
                length=60,
                tcp_flags="S",
            )
            for i, p in enumerate([21, 22, 80, 443, 445, 3306, 5432, 8080])
        ]
        report = analyze_packets(pkts)
        self.assertTrue(any(a["category"] == "Reconnaissance" for a in report["alerts"]))

    def test_csv_export_contains_header_and_rows(self):
        packets = generate_demo_packets(scenario="dns_anomaly", seed=7)
        report = analyze_packets(packets)
        csv_text = packets_to_csv(report["packets"])
        lines = [line for line in csv_text.strip().splitlines() if line]
        self.assertEqual(len(lines), len(packets) + 1)
        self.assertTrue(lines[0].startswith("id,timestamp,src_ip"))


if __name__ == "__main__":
    unittest.main()
