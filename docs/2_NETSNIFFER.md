# NetSniffer Integration in LEGION2

## Overview

NetSniffer is a passive network monitoring component that captures and analyzes network traffic in real-time, enriching the knowledgebase with MAC addresses, vendor information, and passive OS detection. It operates alongside the active scanning tools (masscan and nmap) as a first-class **Source** in the unified streaming pipeline architecture.

## Architecture: The Three-Tier Scanning Strategy

LEGION2 uses a three-tier scanning approach that combines speed, depth, and passive intelligence:

### 1. **Massmap** - Unified Active Scanning (Masscan + Nmap)

**What is Massmap?**

Massmap is the unified scanning strategy that intelligently combines `masscan` (speed) and `nmap` (depth) into a single, optimized workflow. It's not a separate tool, but rather a **smart orchestration layer** that decides when to use each scanner based on network size and existing knowledge.

**How Massmap Works:**

```md
User Initiates Scan
    ↓
create_massmap_plan() analyzes:
    - Target network size (IP count)
    - Existing hosts in database
    - Scan type (quick/comprehensive/stealth)
    ↓
Decision Logic:
    ├─ Large network (>100 IPs) + No existing hosts?
    │   └─ Phase 1: Masscan (fast discovery)
    │       └─ Scans common ports (1-1000) at high rate
    │       └─ Results stored in database
    │
    └─ Phase 2: Nmap (detailed analysis)
        ├─ If Masscan ran: Scans discovered hosts from DB
        └─ If no Masscan: Scans original targets
        └─ Full service detection, OS fingerprinting, NSE scripts
```

**Massmap Decision Logic:**

- **Quick scans on large networks (>100 IPs)**: Always uses masscan first for rapid discovery
- **Other scans on large networks**: Uses masscan only if no existing hosts found in target range
- **Small networks or existing hosts**: Skips masscan, goes directly to nmap
- **Always follows with nmap**: For detailed service detection, OS fingerprinting, and vulnerability scanning

**Massmap Benefits:**

1. **Speed**: Masscan discovers hosts/ports in seconds on large networks
2. **Depth**: Nmap provides comprehensive analysis on discovered targets
3. **Efficiency**: Avoids redundant scanning when hosts already exist
4. **Adaptive**: Automatically adjusts strategy based on network size and existing data

### 2. **NetSniffer** - Passive Network Intelligence

**What is NetSniffer?**

NetSniffer is a **passive** packet capture and analysis tool that monitors network traffic without sending any packets. It enriches the knowledgebase with information that active scanners cannot easily obtain:

- **MAC addresses** (Layer 2 information)
- **Vendor identification** (OUI lookup from MAC addresses)
- **Passive OS detection** (TTL fingerprinting, TCP window sizes)
- **Network topology** (host-to-host communication patterns)
- **Service discovery** (passive observation of responses)

**NetSniffer's Role in the Scanner Ecosystem:**

```md
┌─────────────────────────────────────────────────────────────┐
│              LEGION2 Scanning Ecosystem                      │
└─────────────────────────────────────────────────────────────┘

┌──────────────┐    ┌──────────────┐    ┌──────────────┐
│   Masscan    │    │     Nmap     │    │  NetSniffer  │
│  (Discovery) │    │  (Analysis)  │    │  (Enrichment)│
└──────────────┘    └──────────────┘    └──────────────┘
      │                    │                    │
      │ Fast port scan     │ Deep analysis      │ Passive monitoring
      │ (millions/sec)     │ (OS, services)    │ (MAC, vendor, OS)
      │                    │                    │
      └────────────────────┴────────────────────┘
                          │
                          ↓
              ┌───────────────────────┐
              │   Unified Pipeline     │
              │  (Source → Transform)  │
              └───────────────────────┘
                          │
                          ↓
              ┌───────────────────────┐
              │   Knowledgebase (DB)   │
              │  + UI (React/Zustand)  │
              └───────────────────────┘
```

**When to Use NetSniffer:**

1. **After initial scans**: Once hosts are discovered via massmap, start NetSniffer to enrich them with MAC/vendor/OS data
2. **Continuous monitoring**: Run alongside active scans to capture traffic patterns
3. **Stealth operations**: Passive monitoring doesn't send packets, avoiding detection
4. **IoT device discovery**: Captures "back-noise" from IoT devices (SSDP, mDNS, NetBIOS)

## NetSniffer Integration Architecture

### Source Trait Implementation

NetSniffer implements the `Source` trait, making it a first-class component in the streaming pipeline:

```rust
impl Source for NetSnifferSource {
    async fn start(&self, plan: &Plan) -> Result<ObsStream> {
        // 1. Open pcap capture on specified interface
        // 2. Apply BPF filters (tcp, udp, icmp)
        // 3. Parse packets with etherparse
        // 4. Convert packets → Observations
        // 5. Return ObsStream for pipeline processing
    }
}
```

### Streaming Pipeline Flow

```md
NetSnifferSource.start()
    ↓
┌─────────────────────────────────────┐
│      Packet Capture (Blocking)       │
│  - Spawn blocking task (pcap::next) │
│  - Channel → Async stream            │
│  - Parse: etherparse → PktMeta      │
└─────────────────────────────────────┘
    ↓
┌─────────────────────────────────────┐
│   Packet → Observation Mapping      │
│  - TCP SYN-ACK → Service obs        │
│  - Unique IP → Host obs              │
│  - MAC address → Host enrichment     │
│  - TTL → OS fingerprint hint         │
└─────────────────────────────────────┘
    ↓
Raw Observation Stream (ObsStream)
    ↓
Transform Pipeline (if specified in Plan)
    ├─ MacEnrichmentTransform (OUI lookup)
    ├─ PassiveOsTransform (TTL/OS detection)
    └─ IpEnrichmentTransform (normalize IPs)
    ↓
Processed Observation Stream
    ↓
Broadcast Channel (to multiple sinks)
    ├─ UiSink → Tauri events (obs:host, obs:service)
    ├─ DbSink → Encrypted SQLite database
    └─ VulnerabilityAnalysisSink → Analysis
```

### Plan Configuration

NetSniffer is invoked via a `Plan` configuration:

```rust
Plan::netsniffer(scan_id, interface)
    - scan_id: UUID for scan session
    - interface: Network interface name (or "default")
    - source_type: "netsniffer"
    - modules: ["mac_enrichment", "passive_os"]
    - sink_types: ["ui", "db"]
```

### Frontend Integration

The frontend exposes NetSniffer via a **purple button** in the Scanner tab:

- **Location**: Below the scan form in the left panel
- **Enabled when**: At least one host has been discovered (from massmap scans)
- **Disabled when**: No hosts discovered or scan in progress
- **Action**: Calls `startNetsniffer()` which creates a netsniffer Plan and executes it via `engine_execute()`

**Frontend Flow:**

```typescript
User clicks "Start Network Sniffer" button
    ↓
appStore.startNetsniffer('default')
    ↓
invoke('create_netsniffer_plan', { scanId, interface })
    ↓
invoke('engine_execute', { plan })
    ↓
Backend starts NetSnifferSource
    ↓
Observations flow to:
    - UiSink → Tauri events → Frontend stores
    - DbSink → Database updates
    ↓
Frontend automatically updates via:
    - hostStore listens to 'obs:host' events
    - appStore listens to 'obs:service', 'obs:metric' events
```

## NetSniffer Observation Types

### Host Observations

NetSniffer enriches host observations with:

- **MAC address**: Layer 2 address from ARP/Ethernet headers
- **Vendor**: OUI lookup from MAC address (first 3 bytes)
- **OS hints**: TTL values, TCP window sizes, TCP options
- **First seen**: Timestamp of first packet from host
- **Last seen**: Timestamp of most recent packet

### Service Observations

- **Passive service detection**: TCP SYN-ACK responses indicate open ports
- **Protocol identification**: TCP flags, port numbers
- **Service hints**: Common port mappings (80→HTTP, 443→HTTPS)

### Metric Observations

- **Packet count**: Total packets captured
- **Discovery rate**: New hosts/services per minute
- **Status**: "listening", "cancelled", "waiting"

## Packet Processing Pipeline

### 1. Capture Phase

```rust
// Spawn blocking task (pcap operations are blocking)
tokio::task::spawn_blocking(move || {
    let mut cap = Capture::from_device(dev)?
        .promisc(true)
        .timeout(100)
        .buffer_size(8 << 20)  // 8MB buffer
        .open()?;
    
    cap.filter("tcp or udp or icmp", true)?;
    
    loop {
        match cap.next_packet() {
            Ok(packet) => {
                // Send to async channel
                packet_tx.send(packet_info)?;
            }
            Err(TimeoutExpired) => continue,  // Normal timeout
            Err(e) => /* handle error */
        }
    }
});
```

### 2. Parsing Phase

```rust
// Async stream processing
let stream = stream::unfold(packet_rx, |mut rx| async move {
    if let Some(packet_info) = rx.recv().await {
        // Parse with etherparse
        if let Some(pkt_meta) = handle_packet_with_ts(
            &packet_info.data,
            packet_info.ts_sec,
            packet_info.ts_usec,
            packet_info.len,
            "scanner",
            &interface
        ) {
            // Convert to observations
            let observations = NetSnifferSource::pkt_to_observation(pkt_meta, scan_id);
            return Some((obs, rx));
        }
    }
    None
});
```

### 3. Observation Mapping

**TCP SYN-ACK → Service Observation:**

```rust
Observation {
    kind: ObservationKind::Service,
    fields: {
        "ip": source_ip,
        "port": dst_port,
        "protocol": "tcp",
        "state": "open",
        "ttl": ttl,
        "vendor": vendor_from_mac,
    }
}
```

**Unique Source IP → Host Observation:**

```rust
Observation {
    kind: ObservationKind::Host,
    fields: {
        "ip": source_ip,
        "mac": mac_address,
        "vendor": oui_lookup(mac),
        "status": "up",
    }
}
```

## Integration with Massmap

NetSniffer complements massmap by providing data that active scanners cannot:

### Massmap Discovers

- ✅ IP addresses
- ✅ Open ports
- ✅ Services (via nmap)
- ✅ OS (via nmap -O)
- ✅ Versions (via nmap -sV)

### NetSniffer Enriches

- ✅ MAC addresses (Layer 2)
- ✅ Vendor identification (OUI)
- ✅ Passive OS hints (TTL fingerprinting)
- ✅ Network topology (host-to-host communication)
- ✅ IoT device discovery (SSDP, mDNS)

### Typical Workflow

```md
1. User runs massmap scan
   └─ Masscan discovers hosts/ports quickly
   └─ Nmap performs detailed analysis

2. User clicks "Start Network Sniffer"
   └─ NetSniffer starts passive monitoring
   └─ Captures traffic from discovered hosts
   └─ Enriches database with MAC/vendor data

3. Continuous enrichment
   └─ NetSniffer updates existing hosts as new packets arrive
   └─ Discovers new hosts not found by active scans
   └─ Provides network topology insights
```

## Registry Integration

NetSniffer is registered in the `Registry` alongside other sources:

```rust
impl Registry {
    pub async fn create_source(&self, plan: &Plan) -> Result<Box<dyn Source>> {
        match plan.source_type.as_str() {
            "masscan" => Ok(Box::new(MasscanScanner::new()?)),
            "nmap" => Ok(Box::new(NmapScanner::new())),
            "netsniffer" => {
                let interface = plan.interface.clone()
                    .unwrap_or_else(|| "default".to_string());
                let scanner = NetSnifferSource::new(interface, output_dir);
                Ok(Box::new(scanner))
            }
            _ => Err(anyhow!("Unknown source type"))
        }
    }
}
```

## Transform Modules

NetSniffer plans can specify transform modules for enrichment:

- **`mac_enrichment`**: OUI lookup for vendor identification
- **`passive_os`**: TTL-based OS fingerprinting
- **`ip_enrichment`**: IP address normalization and validation

These transforms run automatically when specified in the Plan's `modules` field.

## Sink Integration

NetSniffer observations flow to the same sinks as massmap:

1. **UiSink**: Emits Tauri events (`obs:host`, `obs:service`, `obs:metric`)
2. **DbSink**: Persists to encrypted SQLite database
3. **VulnerabilityAnalysisSink**: Analyzes for vulnerabilities (optional)

## Advanced Features

### Multi-Protocol Support

NetSniffer handles multiple protocols:

- **TCP**: SYN-ACK detection, service identification
- **UDP**: Service discovery (SSDP, mDNS, NetBIOS)
- **ICMP**: Host discovery, error messages
- **ARP**: MAC address resolution

### BPF Filtering

Configurable Berkeley Packet Filter (BPF) expressions:

- Default: `"tcp or udp or icmp"`
- Can be customized for specific traffic patterns
- Example: `"tcp and dst port 80"` for HTTP traffic only

### Heartbeat Monitoring

NetSniffer emits periodic heartbeat observations to indicate it's still running:

```rust
Observation {
    kind: ObservationKind::Metric,
    fields: {
        "status": "listening",
        "packet_count": 1234,
    }
}
```

### Cancellation Support

NetSniffer respects the global scan cancellation flag:

```rust
if engine_commands::is_scan_cancelled() {
    log::info!("NetSniffer capture cancelled by user");
    break;
}
```

## Future Enhancements

### Planned Features

1. **TopologyEdge Observations**: Emit topology observations for host-to-host communication
2. **Active Probes Integration**: Trigger small UDP probes (SSDP, mDNS) from `scanners/probes/`
3. **Protocol-Specific Parsing**: Deep packet inspection for HTTP, DNS, etc.
4. **Geo-Location**: ASN lookup for IP addresses
5. **Traffic Analysis**: Bandwidth usage, connection patterns

### Transform Pipeline Expansion

As packet parsing grows complex, consider splitting into dedicated transforms:

- `ServiceParsingTransform`: Protocol detection and service identification
- `IpEnrichmentTransform`: OUI/geo/ASN lookups
- `ProgressTrackingTransform`: Metrics and performance monitoring
- `TopologyTransform`: Network topology graph construction

## Usage Examples

### Starting NetSniffer from Frontend

```typescript
// In appStore.ts
startNetsniffer: async (iface?: string) => {
  const scanId = crypto.randomUUID();
  const interfaceName = iface || 'default';
  
  const plan = await invoke<Plan>('create_netsniffer_plan', {
    scanId,
    interface: interfaceName,
  });
  
  await invoke('engine_execute', { plan });
}
```

### Creating NetSniffer Plan Manually

```rust
// In plan.rs
let plan = Plan::netsniffer(
    scan_id,
    "eth0"  // or "default" for auto-detection
);
```

### Continuous Monitoring Pattern

```rust
// Combine passive monitoring with periodic active scans
let plans = Plan::continuous_monitor(
    scan_id,
    "192.168.1.0/24",
    "eth0"
);
// Returns: [netsniffer_plan, os_detection_plan]
```

## Conclusion

NetSniffer completes LEGION2's three-tier scanning strategy:

1. **Masscan** (Speed): Rapid discovery on large networks
2. **Nmap** (Depth): Comprehensive analysis and enumeration
3. **NetSniffer** (Intelligence): Passive enrichment with MAC/vendor/OS data

All three components feed into the unified streaming pipeline, ensuring consistent data flow to the database and frontend. NetSniffer's passive nature makes it ideal for stealth operations and continuous monitoring, while massmap handles active reconnaissance efficiently.

The integration is seamless: once NetSniffer starts, observations automatically flow through the same pipeline as massmap, updating the UI in real-time via Tauri events and persisting to the encrypted database.
