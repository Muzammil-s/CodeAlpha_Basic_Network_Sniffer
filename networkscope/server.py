"""Local HTTP dashboard server and JSON/CSV export API for NetworkScope."""

import csv
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import io
import json
from pathlib import Path
from typing import Dict, Any
from urllib.parse import urlparse, parse_qs

from .detector import analyze_packets
from .sniffer import generate_demo_packets


WEB_DIR = Path(__file__).resolve().parent.parent / "web"


class DashboardState:
    def __init__(self, initial_report: Dict[str, Any]):
        self.report = initial_report


def packets_to_csv(packets: list) -> str:
    output = io.StringIO()
    fieldnames = [
        "id", "timestamp", "src_ip", "dst_ip", "src_port", "dst_port",
        "protocol", "length", "tcp_flags", "direction", "dns_query", "info",
    ]
    writer = csv.DictWriter(output, fieldnames=fieldnames)
    writer.writeheader()
    for p in packets:
        writer.writerow({k: p.get(k, "") for k in fieldnames})
    return output.getvalue()


def make_handler(state: DashboardState):
    class NetworkScopeHandler(BaseHTTPRequestHandler):
        def log_message(self, format: str, *args: Any) -> None:
            return

        def _send_json(self, data: Any, status: int = 200) -> None:
            body = json.dumps(data, indent=2).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self) -> None:
            parsed = urlparse(self.path)
            path = parsed.path

            if path == "/api/report":
                return self._send_json(state.report)

            if path == "/api/simulate":
                qs = parse_qs(parsed.query)
                scenario = qs.get("scenario", ["mixed"])[0]
                seed = int(qs.get("seed", ["42"])[0])
                packets = generate_demo_packets(scenario=scenario, seed=seed)
                state.report = analyze_packets(packets)
                return self._send_json(state.report)

            if path == "/api/export.json":
                body = json.dumps(state.report, indent=2).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Disposition", 'attachment; filename="networkscope-report.json"')
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return

            if path == "/api/export.csv":
                csv_text = packets_to_csv(state.report["packets"]).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/csv; charset=utf-8")
                self.send_header("Content-Disposition", 'attachment; filename="networkscope-packets.csv"')
                self.send_header("Content-Length", str(len(csv_text)))
                self.end_headers()
                self.wfile.write(csv_text)
                return

            # Serve static dashboard files
            target_name = "index.html" if path in ("/", "") else path.lstrip("/")
            file_path = (WEB_DIR / target_name).resolve()
            if not str(file_path).startswith(str(WEB_DIR.resolve())) or not file_path.is_file():
                self.send_error(404, "Not Found")
                return

            mime = "text/plain; charset=utf-8"
            if file_path.suffix == ".html":
                mime = "text/html; charset=utf-8"
            elif file_path.suffix == ".css":
                mime = "text/css; charset=utf-8"
            elif file_path.suffix == ".js":
                mime = "application/javascript; charset=utf-8"

            data = file_path.read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", mime)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

    return NetworkScopeHandler


def run_dashboard(initial_report: Dict[str, Any], host: str = "127.0.0.1", port: int = 8765) -> None:
    state = DashboardState(initial_report)
    server = ThreadingHTTPServer((host, port), make_handler(state))
    print(f"[NetworkScope] Dashboard running at http://{host}:{port}")
    print("Press Ctrl+C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[NetworkScope] Shutting down dashboard.")
    finally:
        server.server_close()
