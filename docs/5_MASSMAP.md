# Massmap — Unified Scanning Strategy

Massmap is LEGION2's decision engine for multi-phase network scanning. It orchestrates
nmap and masscan in sequence to deliver fast, accurate results at any scale.

---

## Architecture Overview

```
Phase 1 — nmap -sn (ARP ping, ~5s)
  → Discovers alive hosts
  → Captures MAC addresses → vendor lookup → device type hint
  → Result: hosts in DB with status=up, MAC, vendor

Phase 2 — masscan on alive hosts only (~10s)
  → Quick: targeted top-28 common ports at 100,000 pps
  → Comprehensive: all 65535 ports at 100,000 pps
  → Result: open (host, port) pairs in DB

Phase 3 — nmap on alive hosts, ONLY open ports from masscan (<30s/host)
  → -Pn -n (no host discovery, no DNS — both already done)
  → Quick: -sV --version-intensity 2 -T4 --host-timeout 30s
      NSE: banner, http-title, ssh-hostkey
  → Comprehensive: -sV -O -T4 with vuln + http-title scripts
  → Result: service names, version hints, script output per open port
```

**Scan type decision**:

| Condition | Strategy |
|-----------|-----------|
| >100 IPs, quick or comprehensive | All 3 phases |
| ≤100 IPs or hosts already in DB | Phase 1 + Phase 3 (skip masscan) |
| Stealth scan | nmap only: `-sS -T2 -f --randomize-hosts` |

---

## Quick Scan

Designed for network topology and device classification. Target: under 90s for a /24.

### Phase 2 — masscan port list

```
21,22,23,25,53,80,110,111,135,139,143,161,443,445,993,995,
1883,3306,3389,5353,5432,5900,6443,8080,8443,8883,9100,27017
```

Covers: FTP, SSH, Telnet, SMTP, DNS, HTTP, POP3, RPC, SMB, IMAP, SNMP, HTTPS, SMTPS/IMAPS,
MQTT, MySQL, RDP, mDNS, PostgreSQL, VNC, Kubernetes API, HTTP-alt, HTTPS-alt, MQTT-TLS,
JetDirect printing, MongoDB.

### Phase 3 — nmap flags

```
-sV --version-intensity 2 -T4 --host-timeout 30s -Pn -n
--script banner,http-title,ssh-hostkey
```

**Why these NSE scripts**:
- `banner` — raw service banner grab, reveals device type and software version
- `http-title` — page title from port 80/443/8080, identifies web services and admin panels
- `ssh-hostkey` — SSH fingerprint from port 22, distinguishes servers from network devices

**No `-O`** — OS detection is slow. Vendor from ARP (Phase 1) provides sufficient device
type context for topology purposes.

---

## Comprehensive Scan

Full depth scan. All ports, full version detection, OS fingerprinting, vulnerability scripts.

### Phase 2 — masscan port range

```
1-65535
```

### Phase 3 — nmap flags

```
-sV -O -T4 -Pn -p <masscan_open_ports>
--script vuln,http-title
```

---

## Stealth Scan

No masscan. Direct nmap with slow, fragmented packets and randomised host order.

```
nmap -sS -T2 -f --randomize-hosts <targets>
```

---

## Implementation Notes

### Target passing

Targets are passed as **separate arguments**, not a space-joined string:

```rust
// Correct — each target is its own arg
for target in plan.targets.split(|c: char| c == ' ' || c == ',' || c == '\n') {
    let t = target.trim();
    if !t.is_empty() { cmd.arg(t); }
}
```

Passing the whole string as one `cmd.arg()` call causes nmap to treat it as a single
unresolvable hostname and attempt DNS resolution despite `-n`.

### masscan rate

Default: **100,000 pps**. Safe for a LAN /24; completes port sweep in ~10s. User-adjustable
via the rate field in the UI.

### masscan empty XML

When masscan finds no open ports it writes an empty or nearly-empty XML file. LEGION2 checks
file size before parsing: files under 100 bytes produce a quiet `"masscan: no open ports found"`
progress observation and skip the XML parser — no error log.

### Autonomous scanning disabled

`DiscoveryManager::schedule_host_scans()` and `execute_recursive_scans()` are intentional
no-ops. All scanning is user-initiated. The discovery manager struct is retained for API
compatibility but fires no autonomous scans.

### Interface auto-detection

For private address ranges (10.x, 192.168.x, 172.x), LEGION2 auto-detects the local
interface, skipping VPN/tunnel/docker interfaces (wg*, tun*, docker*, virbr*, veth*).

---

## Scan Output Flow

```
masscan XML → XmlParser::parse_masscan_xml()
  → Service observations (ip, port, protocol, state)
  → Queued and emitted via ObsStream

nmap XML → XmlParser::parse_nmap_xml()
  → Host observations (ip, mac, vendor, os_guess)
  → Service observations (port, service_name, version, script_output)
  → All enriched via transform pipeline → UiSink + DbSink
```

---

## Runtime Requirements

masscan and nmap SYN scans require raw socket access:

```bash
# Grant capabilities (run once after each build)
sudo setcap cap_net_raw,cap_net_admin=eip $(which masscan)
sudo setcap cap_net_raw+ep src-tauri/target/release/legion2

# Or run as root
sudo ./legion2
```

---

## Verification Checklist

Quick scan on `10.10.21.0/24`:

- [ ] Phase 1 completes in ~5s, alive hosts appear in logs
- [ ] Phase 2 masscan scans targeted port list (not 65535), completes in ~10s
- [ ] Phase 3 nmap uses `-Pn -n`, scans only open ports, `--host-timeout 30s` enforced
- [ ] Total time under 90s for a /24
- [ ] No `"Initiating Parallel DNS resolution"` in logs
- [ ] No recursive scan loop in backend logs
- [ ] No CVE SQL error in logs
- [ ] Topology tab shows all discovered hosts with open ports and service names
