# Network Traffic Analysis & Mini-IDS

## Technical Report

- **Author:** Sri Hari Aravindan
- **Stack:** Python 3.10 · Scapy · tcpdump · pytest · Docker
- **Deployment:** Local CLI + Docker container + GitHub Actions CI
- **Repository:** github.com/Panca2022/Network-Traffic-Analysis

---

## 1. Abstract

This project is a network security analyzer that captures, parses, and inspects live and offline network traffic to detect insecure protocols, cleartext credentials, and covert channels. It demonstrates practical knowledge of packet-level networking (TCP/IP, TLS, DNS, ARP), signature- and heuristic-based threat detection, and defensive engineering. The tool works in two modes - offline (`pcap_analyzer.py`, parses `.pcap` files) and live (`live_monitor.py`, sniffs an interface in real time) - sharing one detection engine so results always agree. It outputs console, JSON, Markdown, and HTML reports, and can export suspicious packets to a new `.pcap` for further investigation.

## 2. Objectives

- Show cleartext vs. encrypted traffic side by side (HTTP vs. HTTPS).
- Detect credential leakage in HTTP POST bodies, Basic auth headers, cookies, and insecure protocols (FTP/Telnet/POP3).
- Identify covert channels (DNS tunneling, beaconing) and network anomalies (ARP spoofing, port scans).
- Provide a 0-100 risk score to prioritise response.
- Prove understanding of testable, reproducible security tooling.

## 3. Architecture

```text
                       ┌───────────────────┐
   .pcap  ───────────▶ │  pcap_analyzer.py │ ──▶ console / JSON / MD / HTML
                       └────────┬──────────┘
                                │ shares
                                ▼
                       ┌───────────────────┐
   live NIC ──────────▶│  live_monitor.py  │ ──▶ real-time alerts + log
                       └───────────────────┘
                                │
                     ┌──────────┴──────────┐
                     │   Analyzer class    │   ←── rules.yaml (config)
                     │  (single detector)  │
                     └─────────────────────┘
```

- **Single detection engine (`Analyzer`)** - offline and live share code, so a rule that fires offline fires live too.
- **Config-driven rules** - thresholds in `rules.yaml`, no code changes to tune.
- **CLI-first, container-friendly** - the analyzer is a Unix-style tool: stdin/pcap in, reports out.

## 4. Component Breakdown

| Component | Responsibility |
|---|---|
| `pcap_analyzer.py` | Offline analyzer; parses pcap, runs detectors, writes reports. |
| `live_monitor.py` | BPF-filtered sniffer; feeds packets into the same `Analyzer`. |
| `Analyzer` class | Central detection logic: protocols, HTTP parsing, TLS, DNS, ARP, TCP flags. |
| `parse_client_hello()` | Extracts SNI + highest TLS version offered from a ClientHello. |
| `compute_ja3()` | Hashes TLS client fingerprint (MD5 of version:cipher:ext:curves:points). |
| `shannon_entropy()` | Entropy in bits/char - flags random-looking DNS labels. |
| `_track_beaconing()` | Tracks inter-packet intervals; flags low-jitter callbacks. |
| `rules.yaml` | Severity levels, thresholds, allowlist, suspicious ports. |
| `write_html()` / `write_markdown()` | Structured report output. |
| `tests/test_analyzer.py` | Synthetic-packet unit tests. |

## 5. Detections Explained

| Detection | How it works | Why it matters |
|---|---|---|
| Cleartext credentials (HTTP) | Parses `application/x-www-form-urlencoded` POST bodies and query strings; matches key regex (user, pass, token, …). Password values are masked by default. | Demonstrates the risk of HTTP login forms. |
| Basic auth over HTTP | Decodes `Authorization: Basic <base64>` and recovers user/pass. | Basic auth is trivially sniffable. |
| Cookie over HTTP | Detects `Cookie:` header in unencrypted request. | Session hijacking risk. |
| Weak TLS | Parses ClientHello, reads `supported_versions` extension, flags TLS 1.0/1.1. | NIST / PCI DSS forbid TLS < 1.2. |
| FTP / Telnet / POP3 cleartext | Regex on USER / PASS commands on ports 21/23/110. | Legacy insecure protocols. |
| DNS tunneling | Shannon entropy of longest DNS label + length threshold. | Covert C2 exfiltration. |
| Beaconing | Tracks intervals per (src, dst, dport); flags low-jitter cadence. | Classic C2 callback pattern. |
| ARP spoofing | Tracks IP→MAC mappings; flags when one IP claims multiple MACs. | Man-in-the-middle indicator. |
| Port scan | Counts distinct destination ports per source. | Reconnaissance. |
| JA3 fingerprint | MD5 of TLS ClientHello fields. | Client identification without decryption - used in production by Cloudflare, abuse.ch. |

## 6. Risk Scoring Model

```text
score = min(100, Σ (weight per distinct severity+category))
weights = { HIGH: 40, MEDIUM: 15, LOW: 3, INFO: 0 }

labels:
  0-9    LOW
  10-39  MODERATE
  40-69  HIGH
  70-100 CRITICAL
```

**Design choice:** Deduplicate by `(severity, category)` so 100 identical LOW alerts don't outrank a single HIGH. This mirrors how real SIEMs score - severity > volume.

## 7. Design Decisions (justifications for the interview)

- **Scapy over raw sockets** - Scapy gives us HTTP/TLS/DNS layer parsing for free; writing bit-level parsers would add code without teaching anything new.
- **Single Analyzer class shared by offline and live** - prevents rule drift. A rule that fires on a pcap fires in real time, always.
- **Config file over hard-coded thresholds** - turn a script into an operational tool. Analysts tune `rules.yaml`; they never touch Python.
- **Mask passwords by default** - safe by construction. `--show-secrets` is opt-in and documented as lab-only.
- **Multiple output formats** - console for interactive, JSON for SIEM/log pipelines, Markdown for human reports, HTML for management.
- **Docker + GitHub Actions** - reproducible build, and every push is tested. Shows "I ship, not just code".

## 8. Evidence from the Live Capture

The `captures/project_http.pcap` file (4,709 packets, 88 s) contains:

- 157 HTTP packets, including a POST to `testphp.vulnweb.com/userinfo.php` with `uname=test&pass=t***` (password masked).
- 4,363 HTTPS packets - full TLS 1.2 handshakes, ~96.6% of web traffic encrypted.
- Zero readable credentials in the HTTPS capture - confirms that TLS actually protects the payload.

The analyzer output:

```text
Risk: HIGH (43/100)
Alerts: 4 (1 HIGH, 3 LOW)
```

This is exactly the kind of "before vs. after" evidence an interviewer wants: what did we observe, what does it prove, what's the takeaway.

## 9. Testing Strategy

- Unit tests (`pytest`) build synthetic Scapy packets - no network needed, deterministic, fast.
- Coverage includes: credential masking, Basic auth decode, FTP login, ARP spoofing, port scan, empty-password edge case.
- New tests added: DNS tunneling, JA3 computation, allowlist behaviour, severity escalation.
- CI runs on every push via GitHub Actions.

## 10. Limitations (be honest)

- Encrypted traffic is opaque - by design. Only metadata (SNI, sizes, timing) is visible.
- No TCP reassembly beyond a heuristic threshold - a TLS handshake split across many packets might be missed; a future iteration should use `scapy.sessions.TCPSession` for proper stream reassembly.
- JA3 detects client stack, not maliciousness - the fingerprint itself is neutral; it becomes actionable when correlated with threat intel.
- DNS tunneling entropy heuristic - high-entropy legitimate services (e.g., DNSSEC, DoH) can false-positive.
- Passive capture requires being on the same L2 segment (or a mirror port).

## 11. Future Roadmap

| Phase | Item | Rationale |
|---:|---|---|
| 1 | Full TCP stream reassembly (`scapy.sessions`) | Removes the biggest detection gap. |
| 2 | Threat intel lookups (AbuseIPDB, JA3 blacklist) | Turns fingerprint into verdict. |
| 3 | Syslog / Elasticsearch output | SOC integration. |
| 4 | Suricata / Zeek rule compatibility | Leverage existing rule ecosystems. |
| 5 | eBPF-based capture | Kernel-level performance. |
| 6 | Interactive dashboard (FastAPI + Chart.js) | Live visualisation. |

## 12. Summary

> "It's a network security analyzer built on Scapy. It works in two modes - offline and live - sharing a single detection engine so results always agree. It detects cleartext credentials, Basic auth over HTTP, weak TLS, FTP/Telnet logins, DNS tunneling, C2 beaconing, ARP spoofing, and port scans. Passwords are masked by default for safe sharing. It outputs console, JSON, Markdown, and HTML reports, has a configurable rules file, and is Dockerised with CI. The most interesting detection is JA3 - a TLS client fingerprint computed entirely from the handshake, which lets you identify clients without decrypting traffic."
