# LEGION2 Scanner Unity Architecture

## Overview

The Unity branch successfully unifies three scanning components (nmap, masscan, netsniffer) into a cohesive streaming pipeline architecture. Each scanner serves a distinct purpose and their outputs are enriched through a series of transforms before reaching the frontend.

## Three Pillars of Unity

### 1. **NmapScanner** - Comprehensive Analysis
- **Purpose**: Deep service detection, OS fingerprinting, NSE scripts
- **Speed**: Moderate (seconds per host)
- **Depth**: Maximum detail
- **Output**: Host, Service, Script observations with full metadata
- **Integration**: Source trait → ObsStream → Transforms → Sinks

### 2. **MasscanScanner** - Rapid Discovery
- **Purpose**: Fast port scanning across large networks
- **Speed**: Extreme (millions of packets/sec)
- **Depth**: Basic (open/closed ports only)
- **Output**: Host, Service observations (basic state)
- **Integration**: Source trait → ObsStream → Transforms → Sinks

### 3. **NetSnifferSource** - Passive Intelligence
- **Purpose**: Network monitoring, MAC vendor lookup, passive OS detection
- **Speed**: Real-time packet capture
- **Depth**: Network-layer intelligence (L2-L4)
- **Output**: Host observations with MAC/vendor/TTL/TCP fingerprints
- **Integration**: **NEW** - Source trait implemented, fully integrated

## Streaming Pipeline Architecture

```
┌────────────────────────────────────────────────────────────────┐
│                   UNIFIED SCANNER PIPELINE                      │
└────────────────────────────────────────────────────────────────┘

USER INPUT (Plan Configuration)
    │
    ├─ Plan::nmap(scan_id, targets, ports, extra_args)
    ├─ Plan::masscan(scan_id, targets, ports, rate)
    ├─ Plan::netsniffer(scan_id, interface)
    ├─ Plan::hybrid(...)         # masscan → nmap
    └─ Plan::continuous_monitor(...) # netsniffer + periodic nmap
    ↓
ENGINE.execute(plan)
    ↓
REGISTRY.create_source(plan)
    ↓
┌─────────────┬──────────────┬─────────────────┐
│ NmapScanner │ MasscanScanner│ NetSnifferSource│
│ (active)    │ (active)      │ (passive)       │
└─────────────┴──────────────┴─────────────────┘
         │             │              │
         └─────────────┴──────────────┘
                       ↓
              RAW OBSERVATION STREAM
         (Host, Service, Metric observations)
                       ↓
┌──────────────────────────────────────────────┐
│        TRANSFORM PIPELINE (Enrichment)        │
├──────────────────────────────────────────────┤
│ 1. IpEnrichmentTransform                     │
│    - Extract IPs from raw output             │
│    - Normalize IP formats                    │
│                                              │
│ 2. MacEnrichmentTransform ✨ NEW             │
│    - Parse MAC OUI (first 3 bytes)           │
│    - Lookup vendor (VMware, Cisco, Apple...) │
│    - Enrich host observations with vendor    │
│                                              │
│ 3. PassiveOsTransform ✨ NEW                 │
│    - TTL-based OS detection                  │
│    - TCP signature analysis                  │
│    - Window size + MSS + options → OS family │
│    - Confidence scoring                      │
│                                              │
│ 4. ServiceParsingTransform                   │
│    - Parse service banners                   │
│    - Extract product/version                 │
│    - Service classification                  │
│                                              │
│ 5. ProgressTrackingTransform                 │
│    - Extract progress percentages            │
│    - Track scan phases                       │
│                                              │
│ 6. VulnerabilityTransform                    │
│    - Match services to CVEs                  │
│    - Risk scoring                            │
└──────────────────────────────────────────────┘
                       ↓
            ENRICHED OBSERVATION STREAM
                       ↓
┌──────────────────────────────────────────────┐
│          BROADCAST CHANNEL                    │
│  (Distributes to multiple sinks in parallel)  │
└──────────────────────────────────────────────┘
                       ↓
         ┌─────────────┼─────────────┐
         ↓             ↓             ↓
    ┌────────┐   ┌────────┐   ┌──────────┐
    │ UiSink │   │ DbSink │   │ VulnSink │
    └────────┘   └────────┘   └──────────┘
         │             │             │
         ↓             ↓             ↓
   Tauri Events  SQLite DB    Vuln Analysis
   - obs:host    - hosts      - CVE matching
   - obs:service - services   - Exploit lookup
   - obs:progress- vulns      - Correlation
   - obs:metrics
   - obs:done
         ↓
   FRONTEND (React + Zustand)
   - HostTable updates
   - ResultViewer updates
   - NetworkMap updates
   - Live output stream
```

## Data Flow Examples

### Example 1: NetSniffer → MacEnrichment → UiSink

```rust
// 1. NetSniffer captures packet
Packet { src_mac: "B8:27:EB:XX:XX:XX", src_ip: "192.168.1.50", ttl: 64 }
    ↓
// 2. NetSnifferSource converts to Observation
Observation {
    kind: Host,
    fields: {
        "ip": "192.168.1.50",
        "mac_address": "B8:27:EB:XX:XX:XX",
        "ttl": 64,
        "status": "up",
        "source": "netsniffer"
    }
}
    ↓
// 3. MacEnrichmentTransform enriches
Observation {
    kind: Host,
    fields: {
        "ip": "192.168.1.50",
        "mac_address": "B8:27:EB:XX:XX:XX",
        "vendor": "Raspberry Pi Foundation",    // ← ADDED
        "oui": "B8:27:EB",                      // ← ADDED
        "ttl": 64,
        "status": "up"
    }
}
    ↓
// 4. PassiveOsTransform enriches
Observation {
    kind: Host,
    fields: {
        "ip": "192.168.1.50",
        "mac_address": "B8:27:EB:XX:XX:XX",
        "vendor": "Raspberry Pi Foundation",
        "ttl": 64,
        "passive_os": "Linux/Unix (TTL 64)",    // ← ADDED
        "os_detection_method": "passive_ttl",   // ← ADDED
        "passive_os_confidence": 20,            // ← ADDED
        "status": "up"
    }
}
    ↓
// 5. UiSink emits to frontend
HostEvent {
    ip: "192.168.1.50",
    mac: Some("B8:27:EB:XX:XX:XX"),
    vendor: Some("Raspberry Pi Foundation"),
    os: Some("Linux/Unix (TTL 64)"),
    status: "up"
}
    ↓
// 6. Frontend receives Tauri event
Frontend listens on 'obs:host' → Updates HostTable, ResultViewer, NetworkMap
```

### Example 2: Hybrid Scan (Masscan → Nmap + NetSniffer)

```rust
// Phase 1: Masscan - Fast Port Discovery
let plans = Plan::hybrid(
    scan_id,
    "10.0.0.0/24".to_string(),
    "1-65535".to_string(),
    10000  // 10k packets/sec
);

// Masscan finds: 10.0.0.5:22, 10.0.0.5:80, 10.0.0.10:443

// Phase 2: Nmap - Detailed Service Detection
// Uses discovered IPs/ports for targeted deep scan
// Output: SSH (OpenSSH 7.4), HTTP (Apache 2.4), HTTPS (nginx 1.18)

// Phase 3: NetSniffer - Passive Monitoring
// Runs continuously in background
// Enriches: MAC vendors, passive OS fingerprints, network behavior
```

## New Components Created

### 1. NetSnifferSource (src-tauri/src/scanners/netsniffer.rs)

**Implementation**: ✅ Complete
- Source trait integration (lines 905-1156)
- Converts pcap packets → Observations
- Factory method: `NetSnifferSource::new(interface, output_dir)`
- Emits: Host + Service + Metric observations
- Features:
  - BPF filtering for scanner replies
  - 8MB packet buffer
  - Timeout-based non-blocking capture
  - NDJSON logging for audit trail

### 2. MacEnrichmentTransform (src-tauri/src/core/transformer.rs)

**Implementation**: ✅ Complete (lines 205-300)
- OUI database with 18+ common vendors
- MAC format parsing (AA:BB:CC / AA-BB-CC-DD-EE-FF)
- Enriches Host observations with vendor field
- Supports:
  - VMware, VirtualBox, Parallels (virtualization)
  - Google, Apple, Microsoft (major tech)
  - Cisco, TP-Link, D-Link, NETGEAR (networking)
  - Raspberry Pi, Synology (IoT/embedded)

### 3. PassiveOsTransform (src-tauri/src/core/transformer.rs)

**Implementation**: ✅ Complete (lines 302-405)
- TTL-based OS detection (255→Linux, 128→Windows, 64→Linux/macOS)
- TCP signature analysis (window size + TTL + MSS + wscale)
- Confidence scoring (0-100 based on available data)
- Detects:
  - Windows (7/8/10, XP/2003, Server)
  - Linux (2.6.x, 3.x/4.x, Modern Linux)
  - macOS/BSD (10.x, generic)
  - Embedded/IoT devices
  - Network devices/routers

### 4. Enhanced UiSink (src-tauri/src/core/sinks.rs)

**Implementation**: ✅ Complete
- New method: `emit_host_with_enrichment()` (lines 143-183)
- Extracts and emits:
  - MAC address (from `mac_address` or `mac` field)
  - Vendor (from MacEnrichmentTransform)
  - OS (from `os_name` or `passive_os` field)
  - TTL, TCP fingerprints
- Builds detailed progress messages
- Updates HostEvent structure with enriched data

### 5. Module Registry Updates (src-tauri/src/modules.rs)

**Implementation**: ✅ Complete
- Registered: `mac-enrichment` / `mac_enrichment`
- Registered: `passive-os` / `passive_os`
- Factory functions for dynamic transform creation
- Available in Plan module specifications

### 6. Plan Factory Methods (src-tauri/src/plan.rs)

**Implementation**: ✅ Complete
- `Plan::netsniffer(scan_id, interface)` - Passive monitoring
- `Plan::hybrid(scan_id, targets, ports, rate)` - Masscan → Nmap
- `Plan::continuous_monitor(scan_id, targets, interface)` - NetSniffer + periodic Nmap
- Pre-configured module pipelines for each pattern

### 7. Registry Integration (src-tauri/src/core/registry.rs)

**Implementation**: ✅ Complete
- NetSnifferSource registered in `create_source()`
- Factory creates instance from Plan configuration
- Uses interface from Plan or defaults to "default"
- Output directory: `.scans`

## Usage Patterns

### Pattern 1: Passive Network Monitoring

```rust
use legion2::{Plan, Engine};

// Start passive monitoring on eth0
let plan = Plan::netsniffer(
    Uuid::new_v4(),
    "eth0".to_string()
);

// Automatically includes: mac_enrichment, passive_os transforms
engine.execute(plan).await?;

// Frontend receives:
// - Host events with MAC vendors
// - Passive OS fingerprints
// - Network statistics
```

### Pattern 2: Hybrid Active + Passive Scan

```rust
// Fast discovery + deep analysis
let plans = Plan::hybrid(
    scan_id,
    "192.168.1.0/24".to_string(),
    "1-1000".to_string(),
    5000  // masscan rate
);

for plan in plans {
    engine.execute(plan).await?;
}

// Result: Fast port discovery, detailed service info
```

### Pattern 3: Continuous Monitoring

```rust
// Background: passive + periodic active
let plans = Plan::continuous_monitor(
    scan_id,
    "192.168.1.0/24".to_string(),
    "eth0".to_string()
);

tokio::spawn(async move {
    for plan in plans {
        engine.execute(plan).await.ok();
        tokio::time::sleep(Duration::from_secs(3600)).await;
    }
});
```

## Frontend Integration

### Tauri Events Emitted

```typescript
// obs:host - Host discovered with enrichment
interface HostEvent {
    ip: string;
    hostname?: string;
    mac?: string;           // ✨ From netsniffer
    vendor?: string;        // ✨ From MacEnrichmentTransform
    os?: string;            // ✨ From passive_os or nmap
    status: string;
    timestamp: string;
}

// obs:service - Service discovered
interface ServiceEvent {
    ip: string;
    port: number;
    protocol: string;
    service?: string;
    product?: string;
    version?: string;
    timestamp: string;
}

// obs:progress - Live output
interface ProgressEvent {
    message: string;        // ✨ Now includes vendor, OS, TTL
    percentage?: number;
    timestamp: string;
}

// obs:metrics - Performance stats
interface MetricsEvent {
    observations_processed: number;
    hosts_discovered: number;
    services_discovered: number;
    processing_rate: number;  // obs/sec
}

// obs:done - Scan complete
```

### Frontend Listening

```typescript
import { listen } from '@tauri-apps/api/event';

// Listen for enriched host events
listen<HostEvent>('obs:host', (event) => {
    const host = event.payload;
    console.log(`Host: ${host.ip}, Vendor: ${host.vendor}, OS: ${host.os}`);

    // Update Zustand store
    hostStore.addHost(host);
});

// Listen for progress with enriched details
listen<ProgressEvent>('obs:progress', (event) => {
    const msg = event.payload.message;
    // Example: "Host discovered: 192.168.1.50 - up [vendor: Raspberry Pi Foundation, OS: Linux/Unix (TTL 64), TTL: 64]"
    appStore.addOutput(msg);
});
```

## Testing the Unity

### Test 1: NetSniffer Integration

```bash
# Terminal 1: Start LEGION2 with netsniffer
cd src-tauri
cargo run

# Frontend: Execute Plan
Plan::netsniffer(scan_id, "eth0")

# Expected Output:
# - MAC addresses captured from packets
# - Vendors resolved (Raspberry Pi, Cisco, etc.)
# - Passive OS guesses from TTL
# - Real-time updates in frontend
```

### Test 2: Hybrid Scan

```bash
# Execute hybrid plan
Plan::hybrid(scan_id, "192.168.1.0/24", "1-65535", 10000)

# Phase 1 (Masscan): ~10 seconds for 65k ports across /24
# Phase 2 (Nmap): Detailed scan of discovered hosts/ports
# Result: Fast + comprehensive coverage
```

### Test 3: Continuous Monitoring

```bash
# Start continuous monitoring
Plan::continuous_monitor(scan_id, "192.168.1.0/24", "eth0")

# NetSniffer runs continuously
# Nmap runs every hour
# Result: Real-time passive intelligence + periodic active validation
```

## Architecture Benefits

### 1. **Modularity**
- Each scanner is a standalone Source
- Transforms are pluggable and chainable
- Easy to add new scanners or enrichment logic

### 2. **Observability**
- Unified Observation data model
- Consistent logging and metrics
- Full audit trail via NDJSON logs

### 3. **Performance**
- Streaming architecture (no memory buffering)
- Parallel sink processing (UI + DB + Vuln)
- Non-blocking async operations

### 4. **Extensibility**
- New transforms via module registry
- Custom scan patterns via Plan builders
- Plugin-like architecture

### 5. **User Experience**
- Real-time UI updates
- Detailed progress messages
- Enriched host information (MAC, vendor, OS)

## Next Steps

### Phase 1: XML Observation Integration ✅ COMPLETE
- ✅ XML parsing integrated into scanner observation streams
- ✅ nmap.rs: XML observations queued and emitted after scan completes (lines 187-298)
- ✅ masscan.rs: XML observations queued and emitted after scan completes (lines 325-438)
- ✅ Observations flow through Transform → Sink pipeline automatically
- ✅ DbSink receives and stores all XML observations (Host, Service, Script data)

### Phase 2: ScannerEngine Orchestration ⏳
- Multi-stage scan coordination
- Queue management
- Priority scheduling

### Phase 3: Advanced Transforms
- IoT device classification (SSDP, mDNS)
- Network topology mapping
- Behavior analysis

### Phase 4: Testing & Validation
- Integration tests for unified pipeline
- Performance benchmarks
- Frontend E2E tests

## Summary

The Unity branch successfully integrates three scanning paradigms:
- **Active Fast** (masscan): Rapid discovery
- **Active Deep** (nmap): Comprehensive analysis
- **Passive** (netsniffer): Continuous intelligence

All three flow through a unified streaming pipeline with modular transforms, enriching observations with MAC vendors, passive OS detection, and service intelligence before reaching the frontend via Tauri events and persisting to an encrypted SQLite database.

**Status**: ✅ Core unity architecture complete and functional
