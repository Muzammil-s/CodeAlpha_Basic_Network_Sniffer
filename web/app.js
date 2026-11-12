/* NetworkScope Dashboard Client (works with Python API server AND standalone static mode) */

let currentReport = null;
let isPythonBackend = false;

function shannonEntropy(text) {
  if (!text) return 0;
  const freq = {};
  for (const ch of text) freq[ch] = (freq[ch] || 0) + 1;
  let ent = 0;
  for (const k of Object.keys(freq)) {
    const p = freq[k] / text.length;
    ent -= p * Math.log2(p);
  }
  return ent;
}

function generateClientDemoPackets(scenario = "mixed") {
  const baseMs = Date.UTC(2026, 10, 12, 16, 30, 0);
  const packets = [];
  let id = 1;
  let offset = 0;
  const add = (src_ip, dst_ip, src_port, dst_port, protocol, length, tcp_flags, info, dns_query = null, payload_preview = "") => {
    offset += 25;
    packets.push({
      id: id++,
      timestamp: new Date(baseMs + offset).toISOString(),
      src_ip, dst_ip, src_port, dst_port, protocol, length, tcp_flags, info, dns_query, payload_preview,
      direction: src_ip.startsWith("192.168.") && !dst_ip.startsWith("192.168.") ? "outbound" : (!src_ip.startsWith("192.168.") && dst_ip.startsWith("192.168.") ? "inbound" : "internal")
    });
  };

  const domains = ["api.github.com", "cdn.jsdelivr.net", "pypi.org", "registry.npmjs.org"];
  domains.forEach((dom, i) => {
    const sport = 51000 + i * 13;
    add("192.168.10.24", "1.1.1.1", sport, 53, "DNS", 74, "", `Standard query A ${dom}`, dom);
    add("1.1.1.1", "192.168.10.24", 53, sport, "DNS", 98, "", `Standard query response A ${dom}`);
    const dst = `140.82.113.${4 + i}`;
    add("192.168.10.24", dst, sport + 1, 443, "TCP", 66, "S", `${sport + 1} -> 443 [SYN]`);
    add(dst, "192.168.10.24", 443, sport + 1, "TCP", 66, "SA", `443 -> ${sport + 1} [SYN, ACK]`);
    add("192.168.10.24", dst, sport + 1, 443, "TCP", 920, "PA", "TLSv1.3 Application Data");
  });

  add("192.168.10.24", "192.168.10.1", null, null, "ICMP", 74, "", "Echo (ping) request seq=1");
  add("192.168.10.1", "192.168.10.24", null, null, "ICMP", 74, "", "Echo (ping) reply seq=1");

  if (scenario === "mixed" || scenario === "recon") {
    [21, 22, 23, 25, 53, 80, 110, 139, 443, 445, 3306, 3389, 5432, 8080].forEach((port, idx) => {
      add("203.0.113.45", "192.168.10.10", 41200 + idx, port, "TCP", 60, "S", `${41200 + idx} -> ${port} [SYN]`);
    });
  }
  if (scenario === "mixed" || scenario === "cleartext") {
    add("192.168.10.31", "198.51.100.72", 53104, 80, "TCP", 312, "PA", "POST /login HTTP/1.1", null,
      "POST /login HTTP/1.1 Host: legacy.internal username=demo&password=sample_redacted");
  }
  if (scenario === "mixed" || scenario === "dns_anomaly") {
    add("192.168.10.42", "8.8.8.8", 58812, 53, "DNS", 128, "",
      "Standard query TXT 9f4c2a8b7e1d60c3a4f9e2b1d8a7c5e3.telemetry-check.example",
      "9f4c2a8b7e1d60c3a4f9e2b1d8a7c5e3.telemetry-check.example");
  }
  return analyzePacketsClient(packets);
}

function analyzePacketsClient(packets) {
  const protocols = {};
  const portCounts = {};
  const flows = {};
  const scanMap = {};
  const synMap = {};
  const alerts = [];
  let totalBytes = 0;

  for (const pkt of packets) {
    totalBytes += pkt.length || 0;
    protocols[pkt.protocol] = (protocols[pkt.protocol] || 0) + 1;
    if (pkt.dst_port != null) portCounts[pkt.dst_port] = (portCounts[pkt.dst_port] || 0) + 1;

    const fkey = `${pkt.src_ip} -> ${pkt.dst_ip} (${pkt.protocol})`;
    if (!flows[fkey]) {
      flows[fkey] = { flow_key: fkey, src_ip: pkt.src_ip, dst_ip: pkt.dst_ip, protocol: pkt.protocol, packet_count: 0, total_bytes: 0, dst_ports: [] };
    }
    flows[fkey].packet_count += 1;
    flows[fkey].total_bytes += pkt.length || 0;
    if (pkt.dst_port != null && !flows[fkey].dst_ports.includes(pkt.dst_port)) flows[fkey].dst_ports.push(pkt.dst_port);

    if (pkt.protocol === "TCP" && pkt.dst_port != null) {
      const k = `${pkt.src_ip}|${pkt.dst_ip}`;
      if (!scanMap[k]) scanMap[k] = new Set();
      scanMap[k].add(pkt.dst_port);
      if ((pkt.tcp_flags || "").includes("S") && !(pkt.tcp_flags || "").includes("A")) {
        synMap[k] = (synMap[k] || 0) + 1;
      }
    }
    if (pkt.payload_preview && /(password|passwd|token|secret)\s*[=:]/i.test(pkt.payload_preview)) {
      alerts.push({
        id: `ALR-CLR-${pkt.id}`,
        severity: "HIGH",
        category: "Cleartext Credential Exposure",
        title: "Potential Sensitive Parameter in Unencrypted Payload",
        description: `Packet #${pkt.id} (${pkt.src_ip} -> ${pkt.dst_ip}:${pkt.dst_port}) exposed credential parameters over unencrypted transport.`,
        recommendation: "Enforce TLS/HTTPS (443) and rotate exposed test credentials."
      });
    }
    if (pkt.dst_port === 80 || pkt.dst_port === 23 || pkt.dst_port === 21) {
      alerts.push({
        id: `ALR-PORT-${pkt.id}`,
        severity: "MEDIUM",
        category: "Insecure Transport",
        title: `Unencrypted Service Usage on Port ${pkt.dst_port}`,
        description: `Observed traffic from ${pkt.src_ip} to ${pkt.dst_ip}:${pkt.dst_port}.`,
        recommendation: "Migrate service to encrypted transport (HTTPS/SSH/SFTP)."
      });
    }
    if (pkt.dns_query) {
      const sub = pkt.dns_query.split(".")[0];
      const ent = shannonEntropy(sub);
      if (sub.length >= 24 || ent >= 3.85) {
        alerts.push({
          id: `ALR-DNS-${pkt.id}`,
          severity: "MEDIUM",
          category: "DNS Anomaly",
          title: "High-Entropy / Long Subdomain DNS Query",
          description: `Query "${pkt.dns_query}" has subdomain length ${sub.length} and Shannon entropy ${ent.toFixed(2)} bits/char.`,
          recommendation: "Inspect querying host process and check domain against DNS threat logs."
        });
      }
    }
  }

  Object.entries(scanMap).forEach(([k, ports], idx) => {
    if (ports.size >= 8) {
      const [src, dst] = k.split("|");
      alerts.push({
        id: `ALR-SCAN-${idx + 1}`,
        severity: "HIGH",
        category: "Reconnaissance",
        title: `Multi-Port Sweep Detected (${ports.size} distinct ports)`,
        description: `${src} probed ${ports.size} distinct destination ports on ${dst}.`,
        recommendation: "Verify authorized scanning; otherwise block source IP and audit exposed services."
      });
    }
  });

  Object.entries(synMap).forEach(([k, count], idx) => {
    if (count >= 12) {
      const [src, dst] = k.split("|");
      alerts.push({
        id: `ALR-SYN-${idx + 1}`,
        severity: "MEDIUM",
        category: "Availability / Flood Heuristic",
        title: "Elevated Unanswered TCP SYN Burst",
        description: `${src} sent ${count} TCP SYN probes toward ${dst}.`,
        recommendation: "Enable SYN cookies and rate limiting."
      });
    }
  });

  const topPorts = Object.entries(portCounts).map(([port, count]) => ({ port: Number(port), count })).sort((a, b) => b.count - a.count).slice(0, 8);
  const flowList = Object.values(flows).sort((a, b) => b.total_bytes - a.total_bytes);

  return {
    summary: {
      total_packets: packets.length,
      total_bytes: totalBytes,
      unique_flows: flowList.length,
      alert_count: alerts.length,
      high_severity_alerts: alerts.filter(a => a.severity === "HIGH").length,
      medium_severity_alerts: alerts.filter(a => a.severity === "MEDIUM").length,
      protocols,
      top_ports: topPorts
    },
    alerts,
    flows: flowList,
    packets
  };
}

function renderBarList(containerId, entries, maxVal, formatter) {
  const el = document.getElementById(containerId);
  if (!entries.length) {
    el.innerHTML = `<p class="kpi-sub">No data</p>`;
    return;
  }
  el.innerHTML = entries.map(([label, val]) => {
    const pct = Math.max(4, Math.round((val / (maxVal || 1)) * 100));
    return `
      <div class="bar-row">
        <div class="bar-meta"><span>${label}</span><span>${formatter(val)}</span></div>
        <div class="bar-track"><div class="bar-fill" style="width:${pct}%"></div></div>
      </div>
    `;
  }).join("");
}

function renderReport(report) {
  currentReport = report;
  const s = report.summary;
  document.getElementById("kpi-packets").textContent = s.total_packets;
  document.getElementById("kpi-bytes").textContent = `${s.total_bytes.toLocaleString()} B total`;
  document.getElementById("kpi-flows").textContent = s.unique_flows;
  document.getElementById("kpi-alerts").textContent = s.alert_count;
  document.getElementById("kpi-severity").textContent = `${s.high_severity_alerts} High · ${s.medium_severity_alerts} Medium`;

  const protoEntries = Object.entries(s.protocols || {}).sort((a, b) => b[1] - a[1]);
  if (protoEntries.length) {
    document.getElementById("kpi-top-proto").textContent = protoEntries[0][0];
    const share = Math.round((protoEntries[0][1] / Math.max(1, s.total_packets)) * 100);
    document.getElementById("kpi-proto-share").textContent = `${share}% of captured traffic`;
  }

  renderBarList("protocol-bars", protoEntries, protoEntries[0]?.[1] || 1, v => `${v} pkts`);
  const portEntries = (s.top_ports || []).map(p => [`Port ${p.port}`, p.count]);
  renderBarList("port-bars", portEntries, portEntries[0]?.[1] || 1, v => `${v} hits`);

  document.getElementById("alert-count-badge").textContent = report.alerts.length;
  const alertsEl = document.getElementById("alerts-list");
  if (!report.alerts.length) {
    alertsEl.innerHTML = `<p class="kpi-sub">No heuristic anomalies detected in this capture.</p>`;
  } else {
    alertsEl.innerHTML = report.alerts.map(a => `
      <div class="alert-card sev-${a.severity}">
        <div class="alert-head">
          <span>${a.title}</span>
          <span class="sev-tag">${a.severity}</span>
        </div>
        <p class="alert-desc">${a.description}</p>
        <p class="alert-rec">Mitigation: ${a.recommendation}</p>
      </div>
    `).join("");
  }

  document.getElementById("flows-tbody").innerHTML = report.flows.map(f => `
    <tr>
      <td class="mono">${f.flow_key}</td>
      <td>${f.protocol}</td>
      <td>${f.packet_count}</td>
      <td>${f.total_bytes.toLocaleString()} B</td>
      <td class="mono">${(f.dst_ports || []).slice(0, 8).join(", ") || "—"}</td>
    </tr>
  `).join("");

  renderPacketTable();
}

function renderPacketTable() {
  if (!currentReport) return;
  const query = document.getElementById("packet-search").value.trim().toLowerCase();
  const proto = document.getElementById("proto-filter").value;
  const filtered = currentReport.packets.filter(p => {
    if (proto !== "ALL" && p.protocol !== proto) return false;
    if (!query) return true;
    const hay = `${p.src_ip} ${p.dst_ip} ${p.src_port || ""} ${p.dst_port || ""} ${p.info || ""} ${p.dns_query || ""}`.toLowerCase();
    return hay.includes(query);
  });

  document.getElementById("packets-tbody").innerHTML = filtered.map(p => `
    <tr>
      <td class="mono">${p.id}</td>
      <td class="mono">${(p.timestamp || "").replace("T", " ").slice(0, 19)}</td>
      <td>${p.protocol}</td>
      <td class="mono">${p.src_ip}${p.src_port ? ":" + p.src_port : ""}</td>
      <td class="mono">${p.dst_ip}${p.dst_port ? ":" + p.dst_port : ""}</td>
      <td>${p.direction || "—"}</td>
      <td>${p.length} B</td>
      <td class="mono info-cell" title="${(p.info || "").replace(/"/g, "&quot;")}">${p.info || ""}</td>
    </tr>
  `).join("");
}

function downloadBlob(filename, content, type) {
  const blob = new Blob([content], { type });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

async function init() {
  const modePill = document.getElementById("mode-pill");
  const isStaticHost = window.location.hostname.endsWith(".vercel.app") || window.location.hostname.endsWith(".github.io");
  if (isStaticHost) {
    isPythonBackend = false;
    modePill.textContent = "Interactive Replay Mode";
    modePill.className = "pill pill-info";
    renderReport(generateClientDemoPackets("mixed"));
  } else {
    try {
      const res = await fetch("/api/report");
      if (res.ok && res.headers.get("content-type")?.includes("application/json")) {
        const data = await res.json();
        isPythonBackend = true;
        modePill.textContent = "Python Engine Connected";
        modePill.className = "pill pill-live";
        renderReport(data);
      } else {
        throw new Error("Static mode");
      }
    } catch {
      isPythonBackend = false;
      modePill.textContent = "Interactive Replay Mode";
      modePill.className = "pill pill-info";
      renderReport(generateClientDemoPackets("mixed"));
    }
  }

  document.getElementById("btn-simulate").addEventListener("click", async () => {
    const scenario = document.getElementById("scenario-select").value;
    if (isPythonBackend) {
      const res = await fetch(`/api/simulate?scenario=${encodeURIComponent(scenario)}`);
      renderReport(await res.json());
    } else {
      renderReport(generateClientDemoPackets(scenario));
    }
  });

  document.getElementById("packet-search").addEventListener("input", renderPacketTable);
  document.getElementById("proto-filter").addEventListener("change", renderPacketTable);

  document.getElementById("upload-json").addEventListener("change", async (e) => {
    const file = e.target.files?.[0];
    if (!file) return;
    try {
      const parsed = JSON.parse(await file.text());
      if (Array.isArray(parsed.packets)) {
        renderReport(parsed.summary ? parsed : analyzePacketsClient(parsed.packets));
      } else if (Array.isArray(parsed)) {
        renderReport(analyzePacketsClient(parsed));
      } else {
        alert("Invalid JSON: expected NetworkScope report or packet array.");
      }
    } catch (err) {
      alert("Failed to parse JSON file: " + err.message);
    }
  });

  document.getElementById("btn-export-json").addEventListener("click", () => {
    if (!currentReport) return;
    downloadBlob("networkscope-report.json", JSON.stringify(currentReport, null, 2), "application/json");
  });

  document.getElementById("btn-export-csv").addEventListener("click", () => {
    if (!currentReport) return;
    const headers = ["id", "timestamp", "src_ip", "dst_ip", "src_port", "dst_port", "protocol", "length", "tcp_flags", "direction", "dns_query", "info"];
    const rows = currentReport.packets.map(p => headers.map(h => JSON.stringify(p[h] ?? "")).join(","));
    downloadBlob("networkscope-packets.csv", [headers.join(","), ...rows].join("\n"), "text/csv;charset=utf-8");
  });
}

init();
