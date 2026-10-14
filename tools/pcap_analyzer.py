#!/usr/bin/env python3
"""
pcap_analyzer.py - Offline network traffic analyzer and cleartext-credential detector.

Reads a .pcap file (e.g. the ones captured with tcpdump) and produces:
  * protocol breakdown, top talkers, DNS queries
  * extracted HTTP requests
  * TLS (HTTPS) handshake metadata (SNI, TLS version, JA3 fingerprint)
  * security alerts (cleartext credentials, Basic auth, cookies over HTTP,
    insecure protocols, ARP spoofing, port-scan, DNS tunneling, beaconing)
  * a 0-100 risk score
Output: console, optional JSON, Markdown, and HTML reports, plus an optional
suspicious-packet pcap export.

Passwords are MASKED by default. Use --show-secrets only in your own lab.

Usage:
    python3 tools/pcap_analyzer.py captures/project_http.pcap
    python3 tools/pcap_analyzer.py captures/project_http.pcap \
        --json output/result.json --md output/report.md --html output/report.html
"""
import argparse
import base64
import hashlib
import json
import math
import os
import re
import sys
from collections import Counter, defaultdict
from ipaddress import ip_address, ip_network
from pathlib import Path
from urllib.parse import parse_qsl, unquote_plus

import yaml
from scapy.all import (ARP, DNS, DNSQR, IP, IPv6, Raw, TCP, UDP,
                       PcapReader, wrpcap)

# ----------------------------------------------------------------------------
# Configuration
# ----------------------------------------------------------------------------
SENSITIVE_KEYS = re.compile(
    r"^(user(name)?|uname|login|email|pass(word|wd)?|pwd|token|session(id)?|api[_-]?key|auth)$",
    re.I,
)
PASSWORD_KEYS = re.compile(r"^(pass(word|wd)?|pwd|token|api[_-]?key|auth)$", re.I)

# Well-known cleartext protocols (port -> name)
INSECURE_PORTS = {21: "FTP", 23: "Telnet", 25: "SMTP", 110: "POP3", 143: "IMAP", 80: "HTTP"}
HTTP_METHODS = (b"GET ", b"POST ", b"PUT ", b"DELETE ", b"HEAD ", b"OPTIONS ", b"PATCH ")

# Fallback default; can be overridden in rules.yaml (thresholds.port_scan_distinct_ports)
PORT_SCAN_THRESHOLD = 20


def mask(value: str, show: bool = False) -> str:
    """Hide secrets so reports are safe to share."""
    if show or not value:
        return value
    return value[0] + "*" * max(len(value) - 1, 3)


def load_rules(path="tools/rules.yaml"):
    """Load thresholds/config; fall back to safe defaults if file missing."""
    defaults = {
        "severity": {},
        "thresholds": {
            "port_scan_distinct_ports": 20,
            "dns_tunnel_label_entropy": 3.8,
            "dns_tunnel_min_label_len": 30,
            "beaconing_min_events": 8,
            "beaconing_max_jitter_pct": 15,
            "tls_low_versions": ["TLS 1.0", "TLS 1.1"],
        },
        "allowlist": {"cidrs": [], "hosts": []},
        "suspicious_ports": {
            "insecure": [21, 23, 25, 110, 143, 80],
            "suspicious_outbound": [],
        },
    }
    p = Path(path)
    if p.exists():
        try:
            with p.open() as f:
                loaded = yaml.safe_load(f) or {}
            for k, v in loaded.items():
                if isinstance(v, dict) and k in defaults:
                    defaults[k].update(v)
                else:
                    defaults[k] = v
        except Exception:
            pass
    return defaults


def severity_rank(s: str) -> int:
    return {"HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}.get(s, 0)


# ----------------------------------------------------------------------------
# TLS helpers
# ----------------------------------------------------------------------------
TLS_VERSIONS = {0x0301: "TLS 1.0", 0x0302: "TLS 1.1", 0x0303: "TLS 1.2", 0x0304: "TLS 1.3"}


def parse_client_hello(data: bytes):
    """Return (sni, highest_tls_version_offered) from a ClientHello, else (None, None).

    NOTE: the record-layer version is useless (clients write TLS 1.0 there for
    compatibility), so we read the handshake version and the
    'supported_versions' extension (0x002b) to find the real maximum.
    """
    try:
        if len(data) < 45 or data[0] != 0x16 or data[5] != 0x01:
            return None, None
        best = int.from_bytes(data[9:11], "big")               # legacy client_version
        pos = 43                                               # 5 rec + 4 hs + 2 ver + 32 random
        pos += 1 + data[pos]                                   # session id
        pos += 2 + int.from_bytes(data[pos:pos + 2], "big")    # cipher suites
        pos += 1 + data[pos]                                   # compression
        ext_end = pos + 2 + int.from_bytes(data[pos:pos + 2], "big")
        pos += 2
        sni = None
        while pos + 4 <= ext_end and pos + 4 <= len(data):
            etype = int.from_bytes(data[pos:pos + 2], "big")
            elen = int.from_bytes(data[pos + 2:pos + 4], "big")
            if etype == 0x0000 and sni is None:                # server_name
                name_len = int.from_bytes(data[pos + 7:pos + 9], "big")
                sni = data[pos + 9:pos + 9 + name_len].decode(errors="ignore")
            elif etype == 0x002B:                              # supported_versions
                n = data[pos + 4]
                for i in range(0, n, 2):
                    v = int.from_bytes(data[pos + 5 + i:pos + 7 + i], "big")
                    if v in TLS_VERSIONS and v > best:
                        best = v
            pos += 4 + elen
        return sni, TLS_VERSIONS.get(best, "unknown")
    except Exception:
        return None, None


def compute_ja3(client_hello: bytes):
    """Return JA3 MD5 fingerprint string, or None if parsing fails.

    JA3 = MD5(SSLVersion,Ciphers,Extensions,EllipticCurves,PointFormats)
    Reference: https://github.com/salesforce/ja3
    """
    try:
        if len(client_hello) < 45 or client_hello[0] != 0x16 or client_hello[5] != 0x01:
            return None
        ssl_ver = int.from_bytes(client_hello[9:11], "big")
        pos = 43
        pos += 1 + client_hello[pos]                              # session id
        cs_len = int.from_bytes(client_hello[pos:pos + 2], "big")
        ciphers = [
            int.from_bytes(client_hello[pos + 2 + i:pos + 4 + i], "big")
            for i in range(0, cs_len, 2)
            if client_hello[pos + 2 + i:pos + 4 + i] != b"\x00\x00"
        ]
        pos += 2 + cs_len
        pos += 1 + client_hello[pos]                              # compression
        ext_len = int.from_bytes(client_hello[pos:pos + 2], "big")
        pos += 2
        ext_end = pos + ext_len
        extensions, curves, point_fmts = [], [], []
        while pos + 4 <= ext_end:
            etype = int.from_bytes(client_hello[pos:pos + 2], "big")
            elen = int.from_bytes(client_hello[pos + 2:pos + 4], "big")
            extensions.append(etype)
            if etype == 0x000A:                                   # supported_groups
                clen = int.from_bytes(client_hello[pos + 4:pos + 6], "big")
                curves = [
                    int.from_bytes(client_hello[pos + 6 + i:pos + 8 + i], "big")
                    for i in range(0, clen, 2)
                ]
            elif etype == 0x000B:                                 # ec_point_formats
                n = client_hello[pos + 4]
                point_fmts = list(client_hello[pos + 5:pos + 5 + n])
            pos += 4 + elen
        ja3_str = ",".join([
            str(ssl_ver),
            "-".join(map(str, ciphers)),
            "-".join(map(str, extensions)),
            "-".join(map(str, curves)),
            "-".join(map(str, point_fmts)),
        ])
        return hashlib.md5(ja3_str.encode()).hexdigest()
    except Exception:
        return None


def shannon_entropy(s: str) -> float:
    """Bits per character. High entropy => random-looking (tunneling/encoded)."""
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def ip_in_allowlist(ip: str, rules) -> bool:
    al = rules.get("allowlist", {})
    if ip in al.get("hosts", []):
        return True
    try:
        addr = ip_address(ip)
    except ValueError:
        return False
    for cidr in al.get("cidrs", []):
        try:
            if addr in ip_network(cidr, strict=False):
                return True
        except ValueError:
            continue
    return False


# ----------------------------------------------------------------------------
# Core analyzer (also reused by live_monitor.py)
# ----------------------------------------------------------------------------
class Analyzer:
    def __init__(self, show_secrets: bool = False, config_path: str = "tools/rules.yaml"):
        self.show_secrets = show_secrets
        self.packets = 0
        self.bytes = 0
        self.first_ts = None
        self.last_ts = None
        self.protocols = Counter()
        self.talkers = Counter()
        self.dns_queries = Counter()
        self.http_requests = []
        self.tls_hellos = []
        self.tls_app_data_packets = 0
        self.alerts = []
        self._alert_keys = set()
        self.arp_table = defaultdict(set)
        self.syn_ports = defaultdict(set)
        self.new_alerts = []

        # Enhanced state
        self.rules = load_rules(config_path)
        self.ja3_hashes = Counter()
        self.dns_tunnel_candidates = []
        self.beacon_tracker = defaultdict(list)
        self.suspicious_packets = []
        self._category_hits = Counter()             # raw hit count per category
        self._escalated_categories = set()          # categories already escalated

    # -- alert helper -------------------------------------------------------
    def alert(self, severity, category, message, evidence=""):
    # Count every invocation, even ones we will deduplicate away.
    # Rationale: escalation is about how often a category fires, not how
    # many distinct messages we've seen.
        self._category_hits[category] += 1
        hits = self._category_hits[category]

        # Emit a one-time escalation alert per category the moment it crosses
        # the threshold. This is separate from the normal alert stream.
        if (hits >= 5 and severity == "LOW"
                and category not in self._escalated_categories):
            self._escalated_categories.add(category)
            esc = {
                "severity": "MEDIUM",
                "category": category,
                "message": f"[escalated from repeat] {category} fired {hits} times",
                "evidence": message[:80],
            }
            self.alerts.append(esc)
            self.new_alerts.append(esc)

        # Normal dedup for the individual alert
        key = (category, message)
        if key in self._alert_keys:
            return
        self._alert_keys.add(key)

        a = {"severity": severity, "category": category,
                "message": message, "evidence": evidence}
        self.alerts.append(a)
        self.new_alerts.append(a)

    # -- main entry ---------------------------------------------------------
    def process(self, pkt):
        self.new_alerts = []
        _pre_alerts = len(self.alerts)
        self.packets += 1
        size = len(pkt)
        self.bytes += size
        ts = float(pkt.time)
        self.first_ts = ts if self.first_ts is None else self.first_ts
        self.last_ts = ts

        if pkt.haslayer(ARP):
            self.protocols["ARP"] += 1
            self._check_arp(pkt[ARP])
        else:
            ip = pkt[IP] if pkt.haslayer(IP) else (pkt[IPv6] if pkt.haslayer(IPv6) else None)
            if ip is None:
                self.protocols["Other"] += 1
            else:
                self.talkers[ip.src] += size
                self.talkers[ip.dst] += size
                if pkt.haslayer(UDP):
                    self._handle_udp(pkt, ip)
                elif pkt.haslayer(TCP):
                    self._handle_tcp(pkt, ip)
                else:
                    self.protocols["Other"] += 1

        # Keep a copy of any packet that generated a new alert (for --pcap-suspects)
        if len(self.alerts) > _pre_alerts and len(self.suspicious_packets) < 500:
            self.suspicious_packets.append(pkt)

    # -- ARP ----------------------------------------------------------------
    def _check_arp(self, arp):
        if arp.op == 2:  # reply
            self.arp_table[arp.psrc].add(arp.hwsrc)
            if len(self.arp_table[arp.psrc]) > 1:
                self.alert("HIGH", "ARP spoofing",
                           f"IP {arp.psrc} claimed by multiple MACs",
                           ", ".join(sorted(self.arp_table[arp.psrc])))

    # -- UDP ----------------------------------------------------------------
    def _handle_udp(self, pkt, ip):
        sport, dport = pkt[UDP].sport, pkt[UDP].dport
        if 5353 in (sport, dport):
            self.protocols["mDNS"] += 1
        elif 53 in (sport, dport):
            self.protocols["DNS"] += 1
            if pkt.haslayer(DNS) and pkt.haslayer(DNSQR) and pkt[DNS].qr == 0:
                name = pkt[DNSQR].qname
                name = name.decode(errors="ignore") if isinstance(name, bytes) else str(name)
                q = name.rstrip(".")
                self.dns_queries[q] += 1

                # DNS tunneling heuristic
                labels = q.split(".")
                longest = max(labels, key=len, default="")
                if (len(longest) >= self.rules["thresholds"]["dns_tunnel_min_label_len"]
                        and shannon_entropy(longest) >= self.rules["thresholds"]["dns_tunnel_label_entropy"]):
                    self.dns_tunnel_candidates.append(q)
                    self.alert(
                        self.rules["severity"].get("dns_tunnel", "HIGH"),
                        "DNS tunneling",
                        f"High-entropy DNS label ({len(longest)} chars) to {ip.dst}",
                        q[:80],
                    )
        elif 443 in (sport, dport):
            self.protocols["QUIC/HTTP3 (encrypted)"] += 1
        else:
            self.protocols["UDP-Other"] += 1

    # -- TCP ----------------------------------------------------------------
    def _handle_tcp(self, pkt, ip):
        tcp = pkt[TCP]
        sport, dport = tcp.sport, tcp.dport
        ts = float(pkt.time)

        # port-scan heuristic: SYN without ACK to many distinct ports
        if tcp.flags & 0x02 and not tcp.flags & 0x10:
            self.syn_ports[ip.src].add(dport)
            threshold = self.rules["thresholds"]["port_scan_distinct_ports"]
            if len(self.syn_ports[ip.src]) == threshold:
                self.alert("MEDIUM", "Port scan",
                           f"{ip.src} sent SYNs to {threshold}+ different ports")

        # beaconing tracker applies to all TCP flows
        self._track_beaconing(ip, tcp, ts)

        payload = bytes(pkt[Raw]) if pkt.haslayer(Raw) else b""

        if 443 in (sport, dport):
            self.protocols["HTTPS/TLS"] += 1
            if payload:
                if payload[0] == 0x17:
                    self.tls_app_data_packets += 1

                sni, ver = parse_client_hello(payload)
                if ver:
                    self.tls_hellos.append({"sni": sni or "-", "version": ver, "dst": ip.dst})

                    # JA3 fingerprint
                    ja3 = compute_ja3(payload)
                    if ja3:
                        self.ja3_hashes[ja3] += 1

                    # suspicious outbound port check
                    if dport in self.rules["suspicious_ports"].get("suspicious_outbound", []):
                        self.alert("MEDIUM", "Suspicious outbound port",
                                   f"Traffic to suspicious port {dport} on {ip.dst}")

                    if ver in self.rules["thresholds"]["tls_low_versions"]:
                        self.alert("MEDIUM", "Weak TLS",
                                   f"Client offers at most {ver} to {sni or ip.dst}")
            return

        # Plaintext protocols
        proto = INSECURE_PORTS.get(dport) or INSECURE_PORTS.get(sport)
        if proto:
            self.protocols[proto + (" (cleartext)" if proto != "HTTP" else "")] += 1
        else:
            self.protocols["TCP-Other"] += 1
        if not payload:
            return

        if proto == "HTTP" or payload.startswith(HTTP_METHODS):
            self._handle_http(payload, ip)
        elif proto in ("FTP", "POP3", "Telnet", "IMAP", "SMTP"):
            self._handle_cleartext_login(payload, proto, ip)

    # -- HTTP ---------------------------------------------------------------
    def _handle_http(self, payload: bytes, ip):
        if not payload.startswith(HTTP_METHODS):
            return
        head, _, body = payload.partition(b"\r\n\r\n")
        lines = head.decode(errors="ignore").split("\r\n")
        try:
            method, path, _ = lines[0].split(" ", 2)
        except ValueError:
            return
        headers = {}
        for l in lines[1:]:
            if ":" in l:
                k, v = l.split(":", 1)
                headers[k.strip().lower()] = v.strip()
        host = headers.get("host", ip.dst)
        req = {"method": method, "host": host, "path": path,
               "user_agent": headers.get("user-agent", "-")}
        self.http_requests.append(req)

        # Basic authentication header
        auth = headers.get("authorization", "")
        if auth.lower().startswith("basic "):
            try:
                user, _, pw = base64.b64decode(auth[6:]).decode(errors="ignore").partition(":")
                self.alert("HIGH", "Basic auth over HTTP",
                           f"HTTP Basic credentials sent to {host}",
                           f"user={user} password={mask(pw, self.show_secrets)}")
            except Exception:
                pass

        # Cookies over HTTP
        if "cookie" in headers:
            self.alert("MEDIUM", "Cookie over HTTP",
                       f"Cookie sent in cleartext to {host}",
                       headers["cookie"][:60] + ("..." if len(headers["cookie"]) > 60 else ""))

        # Form-encoded credentials (POST body or query string)
        pairs = []
        if method == "POST" and "x-www-form-urlencoded" in headers.get("content-type", ""):
            pairs = parse_qsl(body.decode(errors="ignore"), keep_blank_values=True)
        elif "?" in path:
            pairs = parse_qsl(path.split("?", 1)[1], keep_blank_values=True)
        found = [(unquote_plus(k), unquote_plus(v)) for k, v in pairs if SENSITIVE_KEYS.match(k)]

        if any(PASSWORD_KEYS.match(k) and v for k, v in found):
            ev = "  ".join(f"{k}={mask(v, self.show_secrets) if PASSWORD_KEYS.match(k) else v}"
                           for k, v in found)
            self.alert("HIGH", "Cleartext credentials",
                       f"{method} http://{host}{path.split('?')[0]} carries login data", ev)
        else:
            # Suppress the LOW noise for allowlisted hosts
            if not ip_in_allowlist(host, self.rules) and not ip_in_allowlist(ip.dst, self.rules):
                self.alert("LOW", "Unencrypted HTTP", f"Plain HTTP request to {host}")

    # -- FTP / Telnet / POP3 ------------------------------------------------
    def _handle_cleartext_login(self, payload: bytes, proto: str, ip):
        text = payload.decode(errors="ignore").strip()
        m = re.match(r"^(USER|PASS)\s+(.+)$", text, re.I)
        if m and proto in ("FTP", "POP3"):
            val = m.group(2) if m.group(1).upper() == "USER" else mask(m.group(2), self.show_secrets)
            self.alert("HIGH", f"Cleartext {proto} login",
                       f"{proto} {m.group(1).upper()} command sent to {ip.dst}", val)
        else:
            self.alert("MEDIUM", f"Insecure protocol {proto}",
                       f"{proto} traffic observed with {ip.dst} (no encryption)")

    # -- Beaconing ----------------------------------------------------------
    def _track_beaconing(self, ip, tcp, ts):
        """Flag regular callbacks: low-jitter, repeating intervals to same dst."""
        key = (ip.src, ip.dst, tcp.dport)
        self.beacon_tracker[key].append(ts)
        events = self.beacon_tracker[key]
        min_events = self.rules["thresholds"]["beaconing_min_events"]
        if len(events) < min_events:
            return
        deltas = [events[i + 1] - events[i] for i in range(len(events) - 1)]
        if not deltas:
            return
        mean = sum(deltas) / len(deltas)
        if mean < 1.0:                                    # sub-second chatter (ACKs, etc.)
            return
        variance = sum((d - mean) ** 2 for d in deltas) / len(deltas)
        stdev = math.sqrt(variance)
        jitter_pct = (stdev / mean) * 100 if mean else 999
        if jitter_pct <= self.rules["thresholds"]["beaconing_max_jitter_pct"]:
            self.alert(
                self.rules["severity"].get("beaconing", "HIGH"),
                "Beaconing pattern",
                f"Regular callback from {ip.src} to {ip.dst}:{tcp.dport} "
                f"every ~{mean:.1f}s (±{jitter_pct:.0f}%)",
            )

    # -- results ------------------------------------------------------------
    def risk_score(self) -> int:
        kinds = {(a["severity"], a["category"]) for a in self.alerts}
        score = sum({"HIGH": 40, "MEDIUM": 15, "LOW": 3, "INFO": 0}[sev] for sev, _ in kinds)
        return min(score, 100)

    def risk_label(self) -> str:
        s = self.risk_score()
        return "CRITICAL" if s >= 70 else "HIGH" if s >= 40 else "MODERATE" if s >= 10 else "LOW"

    def encrypted_ratio(self):
        tls = self.protocols.get("HTTPS/TLS", 0) + self.protocols.get("QUIC/HTTP3 (encrypted)", 0)
        http = self.protocols.get("HTTP", 0)
        total = tls + http
        return (tls / total * 100) if total else 0.0

    def to_dict(self):
        dur = (self.last_ts - self.first_ts) if self.first_ts else 0
        return {
            "summary": {
                "packets": self.packets,
                "bytes": self.bytes,
                "duration_sec": round(dur, 2),
                "encrypted_web_traffic_pct": round(self.encrypted_ratio(), 1),
                "risk_score": self.risk_score(),
                "risk_level": self.risk_label(),
            },
            "protocols": dict(self.protocols.most_common()),
            "top_talkers": self.talkers.most_common(5),
            "dns_queries": self.dns_queries.most_common(15),
            "http_requests": self.http_requests[:50],
            "tls": {
                "handshakes": len(self.tls_hellos),
                "encrypted_app_data_packets": self.tls_app_data_packets,
                "sites": sorted({h["sni"] for h in self.tls_hellos})[:30],
                "versions": dict(Counter(h["version"] for h in self.tls_hellos)),
            },
            "ja3": dict(self.ja3_hashes.most_common(20)),
            "dns_tunneling_candidates": self.dns_tunnel_candidates[:20],
            "beaconing_pairs": [
                {"src": k[0], "dst": k[1], "dport": k[2], "events": len(v)}
                for k, v in self.beacon_tracker.items()
                if len(v) >= self.rules["thresholds"]["beaconing_min_events"]
            ][:20],
            "alerts": sorted(self.alerts, key=lambda a: -severity_rank(a["severity"])),
        }


# ----------------------------------------------------------------------------
# Reporting
# ----------------------------------------------------------------------------
def print_console(r, name):
    s = r["summary"]
    print(f"\n=== Network Traffic Analysis: {name} ===")
    print(f"Packets: {s['packets']}   Bytes: {s['bytes']}   Duration: {s['duration_sec']}s")
    print(f"Encrypted web traffic: {s['encrypted_web_traffic_pct']}%   "
          f"RISK: {s['risk_level']} ({s['risk_score']}/100)")
    print("\n-- Protocols --")
    for k, v in r["protocols"].items():
        print(f"  {k:28s} {v}")
    print("\n-- Top talkers (bytes) --")
    for ip, b in r["top_talkers"]:
        print(f"  {ip:40s} {b}")
    print(f"\n-- TLS: {r['tls']['handshakes']} handshakes, "
          f"{r['tls']['encrypted_app_data_packets']} encrypted data packets --")
    for site in r["tls"]["sites"][:10]:
        print(f"  {site}")
    if r.get("ja3"):
        print("\n-- JA3 fingerprints --")
        for h, c in list(r["ja3"].items())[:5]:
            print(f"  {h}  ({c} handshakes)")
    print("\n-- Alerts --")
    if not r["alerts"]:
        print("  none")
    for a in r["alerts"]:
        print(f"  [{a['severity']:6s}] {a['category']}: {a['message']}")
        if a["evidence"]:
            print(f"           evidence: {a['evidence']}")
    print()


def write_markdown(r, name, path):
    s = r["summary"]
    L = [f"# Traffic Analysis Report - {name}", "",
         f"- **Packets:** {s['packets']}  |  **Duration:** {s['duration_sec']}s",
         f"- **Encrypted web traffic:** {s['encrypted_web_traffic_pct']}%",
         f"- **Risk:** {s['risk_level']} ({s['risk_score']}/100)", "",
         "## Protocols", "", "| Protocol | Packets |", "|---|---|"]
    L += [f"| {k} | {v} |" for k, v in r["protocols"].items()]
    L += ["", "## Alerts", "", "| Severity | Category | Message | Evidence |", "|---|---|---|---|"]
    L += [f"| {a['severity']} | {a['category']} | {a['message']} | {a['evidence']} |"
          for a in r["alerts"]] or ["| - | - | none | - |"]
    if r.get("ja3"):
        L += ["", "## TLS Client Fingerprints (JA3)", "", "| JA3 MD5 | Handshakes |", "|---|---|"]
        L += [f"| {h} | {c} |" for h, c in r["ja3"].items()]
    L += ["", "## Recommendations", "",
          "- Serve all pages and logins over HTTPS (TLS 1.2+), enable HSTS.",
          "- Replace FTP/Telnet/POP3 with SFTP/SSH/POP3S.",
          "- Never send credentials in query strings; use POST over TLS.",
          "- Mark cookies `Secure; HttpOnly`.", ""]
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(L))


def write_html(r, name, path):
    """Self-contained HTML report (no external assets, opens anywhere)."""
    s = r["summary"]
    risk_color = {"CRITICAL": "#c0392b", "HIGH": "#e67e22",
                  "MODERATE": "#f39c12", "LOW": "#27ae60"}.get(s["risk_level"], "#333")

    def row(cells):
        return "<tr>" + "".join(f"<td>{c}</td>" for c in cells) + "</tr>"

    alerts_html = "".join(
        row([a["severity"], a["category"], a["message"], a.get("evidence", "")])
        for a in r["alerts"]
    ) or '<tr><td colspan="4" style="text-align:center;color:#888">No alerts</td></tr>'

    proto_html = "".join(row([k, v]) for k, v in r["protocols"].items())
    talker_html = "".join(row([ip, b]) for ip, b in r["top_talkers"])
    ja3_html = "".join(row([h, c]) for h, c in r.get("ja3", {}).items()) or \
               '<tr><td colspan="2" style="text-align:center;color:#888">No TLS handshakes</td></tr>'

    html = f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Traffic Analysis — {name}</title>
<style>
 body{{font-family:-apple-system,Segoe UI,Roboto,sans-serif;max-width:960px;margin:40px auto;padding:0 20px;color:#222}}
 h1{{border-bottom:2px solid #333;padding-bottom:8px}}
 h2{{margin-top:32px;border-left:4px solid #333;padding-left:10px}}
 table{{width:100%;border-collapse:collapse;margin:12px 0}}
 th,td{{border:1px solid #ddd;padding:8px 12px;text-align:left;font-size:14px}}
 th{{background:#f4f4f4;font-weight:600}}
 .risk{{font-size:20px;font-weight:700;color:{risk_color}}}
 .summary{{display:grid;grid-template-columns:repeat(4,1fr);gap:16px;margin:20px 0}}
 .card{{background:#f9f9f9;padding:16px;border-radius:8px;text-align:center}}
 .card b{{display:block;font-size:24px;margin-bottom:4px}}
 code{{background:#f4f4f4;padding:2px 6px;border-radius:4px}}
</style></head><body>
<h1>Traffic Analysis Report</h1>
<p><code>{name}</code></p>

<div class="summary">
  <div class="card"><b>{s['packets']}</b>Packets</div>
  <div class="card"><b>{s['duration_sec']}s</b>Duration</div>
  <div class="card"><b>{s['encrypted_web_traffic_pct']}%</b>Encrypted</div>
  <div class="card"><b class="risk">{s['risk_level']}</b>{s['risk_score']}/100</div>
</div>

<h2>Protocols</h2><table><tr><th>Protocol</th><th>Packets</th></tr>{proto_html}</table>

<h2>Top Talkers</h2><table><tr><th>IP</th><th>Bytes</th></tr>{talker_html}</table>

<h2>Alerts</h2>
<table><tr><th>Severity</th><th>Category</th><th>Message</th><th>Evidence</th></tr>{alerts_html}</table>

<h2>TLS Client Fingerprints (JA3)</h2>
<table><tr><th>JA3 MD5</th><th>Handshakes</th></tr>{ja3_html}</table>

<h2>Recommendations</h2>
<ul>
 <li>Serve all pages and logins over HTTPS (TLS 1.2+), enable HSTS.</li>
 <li>Replace FTP/Telnet/POP3 with SFTP/SSH/POP3S.</li>
 <li>Never send credentials in query strings; use POST over TLS.</li>
 <li>Mark cookies <code>Secure; HttpOnly</code>.</li>
</ul>
</body></html>"""
    with open(path, "w", encoding="utf-8") as f:
        f.write(html)


# ----------------------------------------------------------------------------
def analyze_file(path, show_secrets=False, config_path="tools/rules.yaml") -> Analyzer:
    an = Analyzer(show_secrets, config_path)
    with PcapReader(path) as reader:
        for pkt in reader:
            an.process(pkt)
    if an.protocols.get("HTTP", 0) + an.protocols.get("HTTPS/TLS", 0) == 0:
        an.alert("INFO", "Empty capture",
                 "No HTTP or HTTPS traffic found - results cannot prove anything. "
                 "Re-capture while browsing (use filter: port 80 or port 443).")
    return an


def main():
    ap = argparse.ArgumentParser(description="Analyze a pcap for insecure traffic.")
    ap.add_argument("pcap")
    ap.add_argument("--json", help="write JSON result to this file")
    ap.add_argument("--md", help="write Markdown report to this file")
    ap.add_argument("--html", help="write self-contained HTML report to this file")
    ap.add_argument("--pcap-suspects", help="export alerted packets to this pcap")
    ap.add_argument("--config", default="tools/rules.yaml", help="path to rules.yaml")
    ap.add_argument("--show-secrets", action="store_true",
                    help="do not mask passwords (lab use only)")
    args = ap.parse_args()

    try:
        an = analyze_file(args.pcap, args.show_secrets, args.config)
    except FileNotFoundError:
        sys.exit(f"File not found: {args.pcap}")

    result = an.to_dict()
    print_console(result, args.pcap)

    # Ensure output directories exist
    for out in (args.json, args.md, args.html, args.pcap_suspects):
        if out and os.path.dirname(out):
            os.makedirs(os.path.dirname(out), exist_ok=True)

    if args.json:
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump(result, f, indent=2)
        print(f"JSON saved to {args.json}")
    if args.md:
        write_markdown(result, args.pcap, args.md)
        print(f"Markdown report saved to {args.md}")
    if args.html:
        write_html(result, args.pcap, args.html)
        print(f"HTML report saved to {args.html}")
    if args.pcap_suspects and an.suspicious_packets:
        wrpcap(args.pcap_suspects, an.suspicious_packets)
        print(f"{len(an.suspicious_packets)} suspicious packets → {args.pcap_suspects}")


if __name__ == "__main__":
    main()