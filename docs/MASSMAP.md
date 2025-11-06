# Massmap: Unified Scanning Strategy in LEGION2

## Overview

**Massmap** is LEGION2's unified scanning strategy that intelligently orchestrates `masscan` (speed) and `nmap` (depth) into a single, optimized workflow. It's not a separate tool, but rather a **smart decision engine** that automatically determines when to use each scanner based on network size, existing knowledge, and scan type.

## What is Massmap?

Massmap combines the best of both worlds:

- **Masscan**: Lightning-fast port discovery (millions of packets/second)
- **Nmap**: Comprehensive service detection, OS fingerprinting, and vulnerability scanning

The massmap strategy was created to solve the common problem: **"How do I quickly discover hosts on large networks while still getting detailed information?"**

### The Problem It Solves

Traditional scanning approaches face a dilemma:
- **Fast discovery** (masscan): Finds hosts/ports quickly but lacks detail
- **Deep analysis** (nmap): Provides comprehensive information but is slow on large networks

**Massmap solves this by using both in sequence:**
1. **Phase 1**: Masscan rapidly discovers hosts and open ports
2. **Phase 2**: Nmap performs detailed analysis on discovered targets

## How Massmap Works

### Decision Logic

The `create_massmap_plan()` function analyzes the scan request and makes intelligent decisions:

```rust
// Decision factors:
1. Network size (IP count)
2. Existing hosts in database
3. Scan type (quick/comprehensive/stealth)
4. User preferences (OS detection, version detection)
```

### Decision Tree

```
User Initiates Scan
    ↓
Analyze Target Network
    ├─ Count IP addresses in range
    ├─ Check database for existing hosts
    └─ Determine scan type
    ↓
Decision Point:
    ├─ Large network (>100 IPs)?
    │   ├─ Yes → Quick scan?
    │   │   └─ Yes → Always use Masscan + Nmap
    │   │
    │   └─ No → Existing hosts in range?
    │       ├─ No → Use Masscan + Nmap
    │       └─ Yes → Skip Masscan, use Nmap only
    │
    └─ Small network (≤100 IPs)
        └─ Skip Masscan, use Nmap only
```

### Execution Flow

```
┌─────────────────────────────────────────────────────────┐
│              Massmap Execution Flow                     │
└─────────────────────────────────────────────────────────┘

Phase 1: Masscan (if needed)
    ├─ Fast port discovery (1-1000 common ports)
    ├─ High rate scanning (configurable, default 1000 pps)
    ├─ Results stored in database
    └─ Only runs on large networks or when no hosts exist
    ↓
Phase 2: Nmap (always runs)
    ├─ If Masscan ran: Scans discovered hosts from DB
    ├─ If no Masscan: Scans original target range
    ├─ Service detection (-sV)
    ├─ OS fingerprinting (-O, if enabled)
    ├─ NSE scripts (if configured)
    └─ Vulnerability detection (via VulnerabilityAnalysisSink)
```

### Example Scenarios

#### Scenario 1: Large Network, Quick Scan
```
Target: 192.168.0.0/16 (65,536 IPs)
Scan Type: Quick
Existing Hosts: 0

Decision: Use Masscan + Nmap
- Masscan: Scans 1-1000 ports at 1000 pps
- Nmap: Scans discovered hosts with OS detection
Result: Fast discovery + detailed analysis
```

#### Scenario 2: Large Network, Existing Hosts
```
Target: 10.0.0.0/16 (65,536 IPs)
Scan Type: Comprehensive
Existing Hosts: 150 in target range

Decision: Skip Masscan, use Nmap only
- Nmap: Scans original targets with full ports (-p-)
Result: Efficient use of existing knowledge
```

#### Scenario 3: Small Network
```
Target: 192.168.1.1-192.168.1.100 (100 IPs)
Scan Type: Comprehensive

Decision: Skip Masscan, use Nmap only
- Nmap: Full scan with all ports, OS detection, scripts
Result: Nmap is fast enough on small networks
```

## Massmap API in LEGION2

### Frontend Usage

```typescript
// In appStore.ts - automatically called when user starts scan
const massmapResult = await invoke<MassmapResult>('create_massmap_plan', {
  scanId: crypto.randomUUID(),
  targets: "192.168.1.0/24",
  ports: "",  // Empty = default behavior based on scan type
  scanType: "quick",  // or "comprehensive", "stealth"
  extraArgs: [],
  detectOs: true,
  detectVersions: false,
  skipPing: false,
  rate: 1000,  // Masscan rate (packets per second)
  interface: "eth0" || null,  // Optional network interface
});

// Result contains:
// - use_masscan: boolean (whether masscan will be used)
// - masscan_plan: Plan | null (masscan plan if needed)
// - nmap_plan: Plan (always present)
```

### Backend Implementation

```rust
// In plan_commands.rs
#[tauri::command]
pub async fn create_massmap_plan(
    scan_id: Option<String>,
    targets: String,
    ports: String,
    scan_type: String,
    extra_args: Vec<String>,
    detect_os: bool,
    detect_versions: bool,
    skip_ping: bool,
    rate: Option<u64>,
    interface: Option<String>,
    db: State<'_, Arc<Db>>,
) -> Result<MassmapResult, String>
```

### Plan Execution

```rust
// Plans are executed sequentially via engine_execute()
// Frontend automatically waits for each plan to complete

for (const plan of plans) {
  await invoke('engine_execute', { plan });
  // Wait for obs:done event before proceeding
}
```

## Scan Types and Massmap Behavior

### Quick Scan

**Massmap Strategy:**
- **Large networks (>100 IPs)**: Always uses Masscan for discovery
- **Ports**: Common ports (1-1000) for speed
- **Nmap**: Fast timing (-T4), OS detection if enabled
- **Use Case**: Rapid reconnaissance of large networks

**Example:**
```bash
# Masscan phase
masscan -p1-1000 192.168.0.0/16 --rate=1000 --quiet

# Nmap phase
nmap -T4 -O -Pn <discovered_hosts_from_db>
```

### Comprehensive Scan

**Massmap Strategy:**
- **Large networks**: Uses Masscan only if no existing hosts
- **Ports**: All ports (-p-) via nmap
- **Nmap**: Full service detection (-sV), OS detection (-O), aggressive timing (-T4)
- **Use Case**: Thorough analysis with maximum detail

**Example:**
```bash
# Masscan phase (if needed)
masscan -p1-1000 192.168.0.0/16 --rate=1000 --quiet

# Nmap phase
nmap -sS -sV -O -A -T4 -p- <targets>
```

### Stealth Scan

**Massmap Strategy:**
- **Large networks**: Uses Masscan only if no existing hosts
- **Nmap**: Stealth options (-sS, -T2, -f, --randomize-hosts)
- **Use Case**: Avoiding detection while still gathering information

**Example:**
```bash
# Masscan phase (if needed, minimal)
masscan -p1-1000 192.168.0.0/16 --rate=500 --quiet

# Nmap phase
nmap -sS -T2 -f --randomize-hosts <targets>
```

## Masscan Reference

Masscan is a lightning-fast port scanner, ideal for large-scale reconnaissance.

### Basic Syntax

```bash
masscan [options] [targets]
```

### Target Specification

```bash
# IP ranges
masscan 192.168.1.1-192.168.1.254
masscan 10.0.0.0/16

# From file
masscan -iL targets.txt

# Exclude hosts
masscan --exclude 192.168.1.1
masscan --excludefile exclude.txt
```

### Port Specification

```bash
masscan -p80
masscan -p20-100
masscan -p80,443,8080
masscan -p1-65535
```

### Rate & Performance

```bash
masscan --rate 1000           # Packets per second
masscan --rate 1000000       # Max rate
masscan --max-rate 50000     # Alias for --rate
masscan --min-rate 100       # Minimum rate
masscan --max-retries 2      # Retries per port
masscan --wait 10            # Wait for results (seconds)
```

### Output Options

```bash
masscan -oL results.txt       # List format
masscan -oX results.xml      # XML format
masscan -oB results.bin      # Binary format
masscan --output-format json # JSON output (if supported)
```

### Advanced Options

```bash
masscan -S 192.168.1.100              # Spoof source IP
masscan --source-port 60000           # Set source port
masscan --adapter eth0                # Specify network interface
masscan --router-mac 00:11:22:33:44:55 # Set router MAC for ARP
masscan --banners                     # Grab banners (limited)
masscan --pcap results.pcap           # Save packets to PCAP
masscan --open-only                   # Show only open ports
masscan --randomize-hosts             # Randomize scan order
masscan --shard 1/5                   # Split scan into shards
masscan --retries 3                   # Set number of retries
masscan --quiet                       # Quiet mode (used by LEGION2)
```

### Example Advanced Commands

```bash
# Banner grab on top 1000 ports
masscan -p1-1000 --banners 192.168.1.0/24 --rate=500

# Save packets to PCAP for later analysis
masscan -p80 10.0.0.0/8 --pcap out.pcap

# Sharded scan for distributed scanning
masscan -p80 192.168.0.0/16 --shard 2/4 --rate=10000
```

## Nmap Reference

Nmap is a versatile network scanner for discovery, enumeration, and vulnerability assessment.

### Basic Syntax

```bash
nmap [Scan Type(s)] [Options] {targets}
```

### Target Specification

```bash
nmap 192.168.1.1
nmap 192.168.1.1 192.168.1.2
nmap 192.168.1.1-100
nmap 192.168.1.0/24
nmap -iL targets.txt
nmap 192.168.1.0/24 --exclude 192.168.1.1
nmap 192.168.1.0/24 --excludefile exclude.txt
```

### Port Specification

```bash
nmap -p 22
nmap -p 1-1000
nmap -p 80,443,8080
nmap -p-                    # All ports
nmap -p http,https
nmap --top-ports 100
```

### Scan Types

```bash
nmap -sS      # TCP SYN scan (stealth) - default in LEGION2
nmap -sT      # TCP connect scan
nmap -sU      # UDP scan
nmap -sA      # TCP ACK scan
nmap -sW      # Window scan
nmap -sM      # Maimon scan
nmap -sN      # TCP Null scan
nmap -sF      # FIN scan
nmap -sX      # Xmas scan
nmap -sY      # SCTP INIT scan
nmap -sZ      # SCTP COOKIE-ECHO scan
nmap -sO      # IP protocol scan
nmap -sn      # Ping scan (no port scan)
nmap -Pn      # Treat all hosts as online (skip host discovery)
```

### Timing & Performance

```bash
nmap -T0      # Paranoid (slowest)
nmap -T1      # Sneaky
nmap -T2      # Polite
nmap -T3      # Normal
nmap -T4      # Aggressive (used in LEGION2 quick scans)
nmap -T5      # Insane (fastest)
nmap --min-rate 100
nmap --max-rate 1000
nmap --host-timeout 30m
nmap --max-retries 2
nmap --min-parallelism 10
nmap --max-parallelism 100
```

### Output Options

```bash
nmap -oN results.txt         # Normal
nmap -oX results.xml         # XML (parsed by LEGION2)
nmap -oG results.gnmap       # Grepable
nmap -oA basename            # All formats
nmap -v, -vv, -vvv           # Verbosity
nmap -d, -d2                 # Debugging
nmap --reason                # Show reasons for results
nmap --open                  # Show only open ports
nmap --stats-every 10s       # Periodic stats
```

### Service & Version Detection

```bash
nmap -sV                     # Version detection
nmap --version-intensity 5   # Intensity (0-9)
nmap --version-light         # Light version scan
nmap --version-all           # Try all probes
nmap --allports              # Scan all ports for version
```

### OS Detection

```bash
nmap -O                      # OS detection (used in LEGION2)
nmap --osscan-limit          # Limit OS scan to promising targets
nmap --osscan-guess          # Guess OS more aggressively
```

### NSE Scripting Engine

```bash
nmap -sC                     # Default scripts
nmap --script http-title
nmap --script "vuln"         # Vulnerability scripts
nmap --script "http-title and http-headers"
nmap --script-args 'user=admin,pass=admin'
nmap --script-trace
nmap --script-updatedb       # Update script DB
nmap --script-help=ssl-heartbleed
```

### Firewall/IDS Evasion

```bash
nmap -f                      # Fragment packets (used in stealth scans)
nmap --mtu 16                # Set MTU
nmap -D RND:10               # Decoy scan
nmap -S 192.168.1.100        # Spoof source IP
nmap --source-port 53        # Set source port
nmap --data-length 25        # Append random data
nmap --randomize-hosts       # Randomize scan order (used in stealth)
nmap --proxies http://proxy:8080
nmap --spoof-mac 0           # Random MAC
nmap --badsum                # Send packets with invalid checksums
```

### Host Discovery

```bash
nmap -sn                     # Ping scan (host discovery only)
nmap -PE                     # ICMP Echo
nmap -PP                     # ICMP Timestamp
nmap -PM                     # ICMP Netmask
nmap -PS22,80,443            # TCP SYN ping
nmap -PA21,23,80,3389        # TCP ACK ping
nmap -PU53,67,123            # UDP ping
nmap -PR                     # ARP ping
nmap -PO                     # IP protocol ping
nmap -n                      # No DNS resolution
nmap -R                      # Always resolve DNS
```

### Advanced & Miscellaneous

```bash
nmap -A                      # Aggressive: OS, version, script, traceroute
nmap --traceroute            # Trace network path
nmap --iflist                # List interfaces and routes
nmap --packet-trace          # Show all packets sent/received
nmap --reason                # Show why a port is in a particular state
nmap --unprivileged          # Assume unprivileged user
nmap --datadir /path         # Custom data directory
nmap --servicedb /path       # Custom service DB
nmap --version-trace         # Trace version scan
nmap --defeat-rst-ratelimit  # Defeat RST rate limiters
nmap --disable-arp-ping      # Disable ARP discovery
```

### Example Advanced Commands

```bash
# Comprehensive scan with scripts, OS, version, traceroute
nmap -A -p- -T4 -oA fullscan 10.10.10.10

# UDP and TCP scan with service detection
nmap -sS -sU -p U:53,161,T:22,80,443 -sV 192.168.1.1

# Vulnerability scan with NSE
nmap --script vuln 192.168.1.1

# Stealth scan with decoys and spoofed MAC
nmap -sS -D RND:5 --spoof-mac 0 10.0.0.0/24

# Scan with custom data length and randomize hosts
nmap -p 80,443 --data-length 50 --randomize-hosts 172.16.0.0/16
```

## Integration with LEGION2 Pipeline

Massmap plans integrate seamlessly with LEGION2's streaming pipeline architecture:

```
create_massmap_plan()
    ↓
Creates Plan objects:
    ├─ Plan::masscan(...) [optional]
    └─ Plan::nmap(...) [always]
    ↓
engine_execute(plan)
    ↓
Registry.create_source(plan)
    ├─ MasscanScanner (if plan.source_type == "masscan")
    └─ NmapScanner (if plan.source_type == "nmap")
    ↓
Source.start(plan) → ObsStream
    ↓
Transform Pipeline
    ├─ IpEnrichmentTransform
    ├─ ServiceParsingTransform
    └─ ProgressTrackingTransform
    ↓
Broadcast Channel → Multiple Sinks
    ├─ UiSink → Frontend (obs:host, obs:service)
    ├─ DbSink → Database
    └─ VulnerabilityAnalysisSink → Analysis
```

## Benefits of Massmap Strategy

1. **Speed**: Masscan discovers hosts/ports in seconds on large networks
2. **Depth**: Nmap provides comprehensive analysis on discovered targets
3. **Efficiency**: Avoids redundant scanning when hosts already exist
4. **Adaptive**: Automatically adjusts strategy based on network size
5. **User-Friendly**: Single interface, automatic optimization
6. **Database-Driven**: Leverages existing knowledge to avoid redundant work

## Best Practices

1. **Large Networks**: Use quick scans for initial discovery, then comprehensive scans on specific targets
2. **Existing Data**: Massmap automatically skips masscan if hosts already exist in database
3. **Rate Limiting**: Adjust masscan rate based on network capacity (default 1000 pps)
4. **Interface Selection**: Specify network interface for better performance on multi-homed systems
5. **OS Detection**: Enable for comprehensive scans, disable for quick scans to save time

## References

- [Nmap Documentation](https://nmap.org/book/man.html)
- [Masscan GitHub](https://github.com/robertdavidgraham/masscan)
- [LEGION2 Architecture Documentation](../CLAUDE.md)
- [NetSniffer Integration](./NETSNIFFER.md)

---

**Stay safe, scan responsibly!**

