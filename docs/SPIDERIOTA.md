# IoT Spider: Network Discovery and Pivot Point Identification

## Overview

**IoT Spider** is LEGION2's lightweight network discovery system that sends small discovery probes across networks to identify IoT devices, embedded systems, and network infrastructure. It operates by "bouncing" lightweight packets around the network and capturing responses to discover devices with open ports that can serve as pivot points for traffic monitoring and network exploration.

The IoT Spider combines **active probing** (sending discovery packets) with **passive monitoring** (capturing responses via NetSniffer) to create a comprehensive view of IoT devices on the network without the overhead of full port scans.

## What is IoT Spider?

IoT Spider is designed to solve the problem: **"How do I quickly discover vulnerable IoT devices and identify potential pivot points on a network?"**

### The Problem It Solves

Traditional network scanning approaches face challenges with IoT devices:

- **Slow discovery**: Full port scans take too long on large networks
- **Stealth requirements**: Aggressive scanning may trigger security alerts
- **IoT-specific protocols**: Many IoT devices use non-standard discovery protocols
- **Pivot point identification**: Need to identify devices suitable for traffic monitoring

**IoT Spider solves this by:**

1. **Lightweight probes**: Sends minimal discovery packets using IoT-specific protocols
2. **Multicast discovery**: Leverages network multicast for efficient device discovery
3. **Passive capture**: Uses NetSniffer to capture responses without active connection attempts
4. **Protocol-aware**: Implements 6 common IoT discovery protocols
5. **Pivot detection**: Automatically identifies devices suitable as network pivot points

## Architecture

### Integration with LEGION2 Pipeline

IoT Spider integrates seamlessly with LEGION2's unified streaming pipeline architecture:

```
┌─────────────────────────────────────────────────────────────┐
│              IoT Spider Architecture                         │
└─────────────────────────────────────────────────────────────┘

User Initiates IoT Spider Scan
    ↓
Plan::iot_spider(scan_id, targets, protocols)
    ↓
Registry::create_source("iot_probe")
    ↓
┌─────────────────────────────────────────────────────────────┐
│              IoT Probe Source                               │
│  ┌──────────────────────────────────────────────────────┐  │
│  │  1. Start NetSniffer Capture                         │  │
│  │     - BPF filter: IoT protocol ports                  │  │
│  │     - Captures UDP/TCP responses                     │  │
│  └──────────────────────────────────────────────────────┘  │
│                          ↓                                  │
│  ┌──────────────────────────────────────────────────────┐  │
│  │  2. Send Multicast Probes                            │  │
│  │     - SSDP (239.255.255.250:1900)                    │  │
│  │     - mDNS (224.0.0.251:5353)                        │  │
│  │     - WSDD (239.255.255.250:3702)                    │  │
│  │     - CoAP (224.0.1.187:5683)                        │  │
│  └──────────────────────────────────────────────────────┘  │
│                          ↓                                  │
│  ┌──────────────────────────────────────────────────────┐  │
│  │  3. Send Unicast Probes (if targets specified)       │  │
│  │     - SNMP (port 161)                                │  │
│  │     - MQTT (port 1883/8883)                          │  │
│  │     - Targeted protocol probes                       │  │
│  └──────────────────────────────────────────────────────┘  │
│                          ↓                                  │
│  ┌──────────────────────────────────────────────────────┐  │
│  │  4. Match Captured Packets with Probes               │  │
│  │     - Timestamp correlation                          │  │
│  │     - Port-based protocol matching                   │  │
│  │     - Response parsing                                │  │
│  └──────────────────────────────────────────────────────┘  │
│                          ↓                                  │
│  ┌──────────────────────────────────────────────────────┐  │
│  │  5. Generate Observations                            │  │
│  │     - Host observations (device info)                │  │
│  │     - Service observations (protocol/port)           │  │
│  │     - Pivot candidate flags                          │  │
│  └──────────────────────────────────────────────────────┘  │
    ↓
┌─────────────────────────────────────────────────────────────┐
│              Unified Pipeline                                │
│  (Transforms → Sinks → Database/UI)                          │
└─────────────────────────────────────────────────────────────┘
```

### Component Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    IoT Spider Components                      │
└─────────────────────────────────────────────────────────────┘

┌──────────────────────┐
│   iot_probes.rs      │  Protocol implementations
│  ────────────────── │
│  • SSDPProbe         │  UPnP/SSDP discovery
│  • MDNSProbe         │  mDNS/Bonjour discovery
│  • WSDDProbe         │  Web Services Discovery
│  • SNMPProbe         │  SNMP device queries
│  • CoAPProbe         │  CoAP resource discovery
│  • MQTTProbe         │  MQTT broker detection
│  • IoTProbeSender    │  Unified probe sender
└──────────────────────┘
           │
           ↓
┌──────────────────────┐
│ iot_probe_source.rs  │  Source trait implementation
│  ────────────────── │
│  • Probe coordination│  Sends probes, captures responses
│  • Response matching │  Correlates packets with probes
│  • Observation gen   │  Creates Host/Service observations
│  • Pivot detection   │  Identifies pivot candidates
└──────────────────────┘
           │
           ↓
┌──────────────────────┐
│   netsniffer.rs      │  Enhanced packet capture
│  ────────────────── │
│  • BPF filters       │  IoT protocol port filtering
│  • Packet capture    │  Real-time packet monitoring
│  • Protocol parsing  │  Basic packet structure extraction
└──────────────────────┘
```

## Supported Protocols

IoT Spider implements 6 discovery protocols commonly used by IoT devices and network infrastructure:

### 1. SSDP/UPnP (Simple Service Discovery Protocol)

**Purpose**: Discover UPnP-enabled devices (routers, printers, media servers, IoT devices)

**Protocol Details**:
- **Multicast Address**: `239.255.255.250:1900`
- **Protocol**: UDP
- **Probe Type**: M-SEARCH request
- **Response**: HTTP-like headers with device information

**Probe Format**:
```
M-SEARCH * HTTP/1.1
Host: 239.255.255.250:1900
MAN: "ssdp:discover"
MX: 3
ST: ssdp:all
```

**Response Parsing**:
- Extracts `LOCATION` header (device description URL)
- Extracts `USN` (Unique Service Name)
- Extracts `SERVER` header (device type/version)
- Extracts `ST` (Service Type)

**Device Types Discovered**:
- Routers and gateways
- Network printers
- Media servers (DLNA)
- Smart TVs
- IoT cameras
- Home automation devices

**Pivot Potential**: High - UPnP devices often have web management interfaces

### 2. mDNS/DNS-SD (Multicast DNS / DNS Service Discovery)

**Purpose**: Discover devices using Bonjour/ZeroConf (Apple devices, printers, IoT)

**Protocol Details**:
- **Multicast Address**: `224.0.0.251:5353`
- **Protocol**: UDP
- **Probe Type**: DNS query for `_services._dns-sd._udp.local`
- **Response**: DNS PTR records with service information

**Probe Format**:
- DNS query packet requesting PTR records for service discovery

**Response Parsing**:
- Extracts service names from DNS answers
- Parses TXT records for device information
- Identifies device types from service names

**Device Types Discovered**:
- Apple devices (Mac, iPhone, iPad, Apple TV)
- Network printers
- AirPlay devices
- HomeKit devices
- IoT devices with mDNS support

**Pivot Potential**: Medium - Often consumer devices, but may have exposed services

### 3. WSDD (Web Services Dynamic Discovery)

**Purpose**: Discover Windows devices and WCF services

**Protocol Details**:
- **Multicast Address**: `239.255.255.250:3702`
- **Protocol**: UDP
- **Probe Type**: SOAP envelope with Probe action
- **Response**: SOAP ProbeMatch with service information

**Probe Format**:
```xml
<env:Envelope xmlns:env="http://www.w3.org/2003/05/soap-envelope"
              xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing"
              xmlns:wsd="http://schemas.xmlsoap.org/ws/2005/04/discovery">
  <env:Header>
    <wsd:AppSequence InstanceId="..." MessageNumber="1"/>
    <wsa:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</wsa:To>
    <wsa:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</wsa:Action>
    <wsa:MessageID>urn:uuid:...</wsa:MessageID>
  </env:Header>
  <env:Body><wsd:Probe/></env:Body>
</env:Envelope>
```

**Response Parsing**:
- Extracts `MessageID` for correlation
- Extracts `XAddrs` (service addresses)
- Extracts `Types` (service types)

**Device Types Discovered**:
- Windows workstations and servers
- Windows printers
- WCF web services
- Network scanners

**Pivot Potential**: High - Windows devices often have multiple exposed services

### 4. SNMP (Simple Network Management Protocol)

**Purpose**: Query network devices for system information

**Protocol Details**:
- **Port**: `161` (UDP)
- **Protocol**: UDP (unicast only)
- **Probe Type**: SNMP GetRequest for system description (OID 1.3.6.1.2.1.1.1.0)
- **Community**: `public` (default)

**Probe Format**:
- SNMP v2c GetRequest packet
- Queries system description OID

**Response Parsing**:
- Detects SNMP response packets
- Extracts system description (if available)
- Identifies device type from response

**Device Types Discovered**:
- Network switches and routers
- Printers and network devices
- UPS systems
- Environmental monitoring devices
- Industrial control systems

**Pivot Potential**: Very High - Network infrastructure devices with management interfaces

### 5. CoAP (Constrained Application Protocol)

**Purpose**: Discover IoT devices using CoAP resource discovery

**Protocol Details**:
- **Multicast Address**: `224.0.1.187:5683` (multicast) or `5683/5684` (unicast)
- **Protocol**: UDP
- **Probe Type**: CoAP GET request to `/.well-known/core`
- **Response**: Link-Format resource list

**Probe Format**:
- CoAP GET request with Uri-Path options
- Requests `/.well-known/core` resource

**Response Parsing**:
- Extracts CoAP response code
- Parses Link-Format payload
- Identifies available resources

**Device Types Discovered**:
- IoT sensors (temperature, humidity, motion)
- Smart lighting systems
- Home automation devices
- Industrial IoT devices
- Constrained devices (low power)

**Pivot Potential**: Medium - IoT devices may have limited capabilities

### 6. MQTT (Message Queuing Telemetry Transport)

**Purpose**: Discover MQTT brokers (IoT messaging infrastructure)

**Protocol Details**:
- **Ports**: `1883` (non-TLS), `8883` (TLS)
- **Protocol**: TCP (unicast only)
- **Probe Type**: MQTT CONNECT packet
- **Response**: CONNACK with broker information

**Probe Format**:
- MQTT CONNECT packet with client ID
- Protocol level 4 (MQTT 3.1.1)

**Response Parsing**:
- Extracts CONNACK return code
- Identifies broker acceptance/rejection
- Determines broker version (if available)

**Device Types Discovered**:
- MQTT brokers
- IoT messaging infrastructure
- Home automation hubs
- Industrial IoT gateways

**Pivot Potential**: Very High - MQTT brokers are central messaging infrastructure

## How IoT Spider Works

### Execution Flow

```
1. User creates IoT spider plan:
   Plan::iot_spider(scan_id, targets, protocols)

2. Registry creates IoT Probe Source:
   - Parses protocol list from plan
   - Defaults to all protocols if none specified
   - Configures interface and output directory

3. IoT Probe Source starts:
   a. Starts NetSniffer capture with enhanced BPF filter
      - Captures UDP ports: 1900, 5353, 3702, 161, 5683, 5684
      - Captures TCP ports: 1883, 8883
   
   b. Sends multicast probes:
      - SSDP M-SEARCH to 239.255.255.250:1900
      - mDNS query to 224.0.0.251:5353
      - WSDD Probe to 239.255.255.250:3702
      - CoAP GET to 224.0.1.187:5683
      - Records probe timestamps
   
   c. Sends unicast probes (if targets specified):
      - SNMP GetRequest to target:161
      - MQTT CONNECT to target:1883/8883
      - Records probe timestamps
   
   d. Waits for responses (default: 5 seconds)
   
   e. Processes captured packets:
      - Matches packets to probes by port and timestamp
      - Parses protocol-specific responses
      - Extracts device information
   
   f. Generates observations:
      - Host observations with device info
      - Service observations with protocol details
      - Marks pivot candidates

4. Observations flow through pipeline:
   - Transforms enrich data (MAC, OS, CVE)
   - Sinks store in database and emit to UI
```

### Probe-Response Correlation

IoT Spider uses timestamp-based correlation to match captured packets with sent probes:

```rust
// For each captured packet:
1. Extract source IP, source port, destination port
2. Match destination port to protocol:
   - Port 1900 → SSDP
   - Port 5353 → mDNS
   - Port 3702 → WSDD
   - Port 161 → SNMP
   - Port 5683/5684 → CoAP
   - Port 1883/8883 → MQTT

3. Check if probe was sent recently:
   - Find probe timestamp for matching protocol
   - Check if packet timestamp is within timeout window (5 seconds)
   - If match found, parse response

4. Parse protocol-specific response:
   - Extract device information
   - Create observations
```

### Pivot Point Detection

IoT Spider automatically identifies devices suitable as pivot points based on:

1. **Protocol Type**:
   - SSDP/WSDD devices: Often have web management interfaces
   - SNMP devices: Network infrastructure with management capabilities
   - MQTT brokers: Central messaging infrastructure

2. **Device Information**:
   - Multiple exposed services
   - Management interfaces detected
   - Network infrastructure devices

3. **Response Characteristics**:
   - Rich device information in responses
   - Multiple service types advertised
   - Device capabilities indicated

**Pivot Candidate Criteria**:
- Devices responding to SSDP/WSDD (web interfaces likely)
- SNMP-enabled devices (network infrastructure)
- MQTT brokers (central messaging)
- Devices with multiple service types

## Usage

### Basic Usage

```rust
use crate::plan::Plan;
use uuid::Uuid;

// Create IoT spider scan with all protocols
let plan = Plan::iot_spider(
    scan_id,
    "192.168.1.0/24".to_string(),
    vec![] // Empty = use all protocols
);

// Create IoT spider scan with specific protocols
let plan = Plan::iot_spider(
    scan_id,
    "192.168.1.0/24".to_string(),
    vec!["ssdp".to_string(), "mdns".to_string(), "snmp".to_string()]
)
.with_interface("eth0".to_string());
```

### Protocol Selection

```rust
// Use only multicast protocols (SSDP, mDNS, WSDD, CoAP)
let plan = Plan::iot_spider(
    scan_id,
    "192.168.1.0/24".to_string(),
    vec!["ssdp".to_string(), "mdns".to_string(), "wsdd".to_string()]
);

// Use only unicast protocols (SNMP, MQTT)
let plan = Plan::iot_spider(
    scan_id,
    "192.168.1.1,192.168.1.100".to_string(), // Specific targets
    vec!["snmp".to_string(), "mqtt".to_string()]
);
```

### Integration with Engine

```rust
use crate::core::engine::GLOBAL_ENGINE;

// Execute IoT spider scan
let plan = Plan::iot_spider(scan_id, targets, protocols);
GLOBAL_ENGINE.execute(plan).await?;
```

## Observation Structure

### Host Observation

IoT Spider generates Host observations with the following fields:

```json
{
  "kind": "Host",
  "key": "host-192.168.1.100",
  "fields": {
    "ip": "192.168.1.100",
    "iot_protocol": "ssdp",
    "source": "iot_probe",
    "status": "up",
    "device_type": "router",
    "pivot_candidate": true,
    "device_location": "http://192.168.1.100:49152/description.xml",
    "device_usn": "uuid:12345678-1234-1234-1234-123456789abc",
    "device_server": "Linux/3.14 UPnP/1.0 Device/1.0",
    "device_st": "upnp:rootdevice"
  },
  "raw": "HTTP/1.1 200 OK\r\nLOCATION: http://192.168.1.100:49152/description.xml\r\n..."
}
```

### Service Observation

IoT Spider generates Service observations with protocol details:

```json
{
  "kind": "Service",
  "key": "service-192.168.1.100-1900-udp",
  "fields": {
    "ip": "192.168.1.100",
    "port": 1900,
    "protocol": "udp",
    "state": "open",
    "service": "ssdp",
    "source": "iot_probe",
    "location": "http://192.168.1.100:49152/description.xml",
    "usn": "uuid:12345678-1234-1234-1234-123456789abc",
    "server": "Linux/3.14 UPnP/1.0 Device/1.0"
  }
}
```

## Technical Implementation

### Protocol Implementations

All protocol implementations are located in `src-tauri/src/scanners/probes/iot_probes.rs`:

#### SSDP Probe

```rust
pub struct SSDPProbe;

impl SSDPProbe {
    pub fn build_probe() -> Vec<u8> {
        // Builds M-SEARCH HTTP request
    }
    
    pub fn parse_response(data: &[u8]) -> Result<IoTProbeResponse> {
        // Parses HTTP headers from response
        // Extracts LOCATION, USN, SERVER, ST headers
    }
}
```

#### mDNS Probe

```rust
pub struct MDNSProbe;

impl MDNSProbe {
    pub fn build_probe() -> Vec<u8> {
        // Builds DNS query for _services._dns-sd._udp.local
    }
    
    pub fn parse_response(data: &[u8]) -> Result<IoTProbeResponse> {
        // Parses DNS response packet
        // Extracts service records
    }
}
```

#### WSDD Probe

```rust
pub struct WSDDProbe;

impl WSDDProbe {
    pub fn build_probe() -> Vec<u8> {
        // Builds SOAP Probe envelope
    }
    
    pub fn parse_response(data: &[u8]) -> Result<IoTProbeResponse> {
        // Parses SOAP ProbeMatch response
        // Extracts MessageID, XAddrs, Types
    }
}
```

#### SNMP Probe

```rust
pub struct SNMPProbe;

impl SNMPProbe {
    pub fn build_probe(community: &str) -> Vec<u8> {
        // Builds SNMP GetRequest for sysDescr OID
    }
    
    pub fn parse_response(data: &[u8]) -> Result<IoTProbeResponse> {
        // Detects SNMP response packets
        // Extracts system description (basic parsing)
    }
}
```

#### CoAP Probe

```rust
pub struct CoAPProbe;

impl CoAPProbe {
    pub fn build_probe() -> Vec<u8> {
        // Builds CoAP GET request for /.well-known/core
    }
    
    pub fn parse_response(data: &[u8]) -> Result<IoTProbeResponse> {
        // Parses CoAP response
        // Extracts Link-Format resource list
    }
}
```

#### MQTT Probe

```rust
pub struct MQTTProbe;

impl MQTTProbe {
    pub fn build_probe() -> Vec<u8> {
        // Builds MQTT CONNECT packet
    }
    
    pub fn parse_response(data: &[u8]) -> Result<IoTProbeResponse> {
        // Parses MQTT CONNACK response
        // Extracts return code and status
    }
}
```

### Enhanced NetSniffer BPF Filters

NetSniffer has been enhanced to capture IoT protocol responses:

```rust
// Enhanced BPF filter in netsniffer.rs
let bpf_filter = format!(
    "tcp or udp or icmp or \
     (udp and (port 1900 or port 5353 or port 3702 or port 161 or port 5683 or port 5684)) or \
     (tcp and (port 1883 or port 8883))"
);
```

This filter ensures that:
- All standard traffic is captured (tcp/udp/icmp)
- IoT protocol ports are explicitly included
- Responses to probes are captured efficiently

### Source Implementation

The IoT Probe Source (`iot_probe_source.rs`) implements the `Source` trait:

```rust
#[async_trait]
impl Source for IoTProbeSource {
    fn name(&self) -> &'static str {
        "iot_probe"
    }
    
    async fn start(&self, plan: &Plan) -> Result<ObsStream> {
        // 1. Start NetSniffer capture
        // 2. Send multicast probes
        // 3. Send unicast probes (if targets specified)
        // 4. Wait for responses
        // 5. Process captured packets
        // 6. Generate observations
    }
}
```

## Use Cases

### 1. IoT Device Discovery

**Scenario**: Discover all IoT devices on a local network

**Approach**:
```rust
let plan = Plan::iot_spider(
    scan_id,
    "192.168.1.0/24".to_string(),
    vec!["ssdp".to_string(), "mdns".to_string()]
);
```

**Result**: Discovers smart TVs, printers, cameras, home automation devices

### 2. Network Infrastructure Mapping

**Scenario**: Identify network infrastructure devices (routers, switches)

**Approach**:
```rust
let plan = Plan::iot_spider(
    scan_id,
    "10.0.0.0/8".to_string(),
    vec!["snmp".to_string()]
);
```

**Result**: Discovers SNMP-enabled network devices with management interfaces

### 3. Pivot Point Identification

**Scenario**: Find devices suitable for traffic monitoring and pivoting

**Approach**:
```rust
let plan = Plan::iot_spider(
    scan_id,
    targets,
    vec![] // All protocols
)
.with_modules(vec!["vulnerability".to_string()]);
```

**Result**: Identifies devices with:
- Multiple exposed services
- Management interfaces
- Network infrastructure capabilities
- Marked as `pivot_candidate: true`

### 4. Stealth Network Reconnaissance

**Scenario**: Discover devices without triggering security alerts

**Approach**:
```rust
// Use only multicast protocols (no direct connection attempts)
let plan = Plan::iot_spider(
    scan_id,
    "192.168.1.0/24".to_string(),
    vec!["ssdp".to_string(), "mdns".to_string(), "wsdd".to_string()]
);
```

**Result**: Passive discovery using multicast protocols, minimal network footprint

### 5. IoT Security Assessment

**Scenario**: Identify vulnerable IoT devices for security assessment

**Approach**:
```rust
let plan = Plan::iot_spider(
    scan_id,
    targets,
    vec![]
)
.with_modules(vec![
    "service_parsing".to_string(),
    "vulnerability".to_string(),
    "cve_enrichment".to_string()
]);
```

**Result**: Discovers IoT devices and enriches with:
- Device types and versions
- Exposed services
- Known CVEs
- Vulnerability severity

## Integration with Other Components

### NetSniffer Integration

IoT Spider leverages NetSniffer for packet capture:

- **BPF Filters**: Enhanced to capture IoT protocol ports
- **Packet Parsing**: Basic packet structure extraction
- **Response Correlation**: Timestamp-based matching

### Pipeline Integration

IoT Spider observations flow through the standard pipeline:

1. **Transforms**:
   - `ip_enrichment`: Normalizes IP addresses
   - `service_parsing`: Parses service information
   - `vulnerability`: Analyzes for vulnerabilities
   - `cve_enrichment`: Matches CVEs to devices

2. **Sinks**:
   - `ui`: Emits observations to frontend
   - `db`: Stores in encrypted SQLite database
   - `vulnerability`: Runs vulnerability analysis

### Database Storage

IoT Spider observations are stored in the standard database schema:

- **Hosts table**: Device information, MAC addresses, pivot flags
- **Services table**: Protocol details, ports, service types
- **Vulnerabilities table**: CVE mappings, exploit information

## Performance Considerations

### Probe Timing

- **Multicast probes**: Sent sequentially with 100ms delays
- **Unicast probes**: Sent sequentially with 50ms delays
- **Response timeout**: Default 5 seconds (configurable)
- **Total scan time**: ~1-2 seconds for multicast + timeout

### Network Impact

- **Minimal footprint**: Only sends discovery packets, no connection attempts
- **Multicast TTL**: Limited to local network (TTL=2)
- **Rate limiting**: Built-in delays prevent network flooding
- **Stealth**: Passive capture doesn't trigger most IDS/IPS systems

### Scalability

- **Small networks** (< 100 IPs): Complete scan in seconds
- **Medium networks** (100-1000 IPs): Complete scan in < 1 minute
- **Large networks** (> 1000 IPs): Focus on multicast discovery, selective unicast

## Limitations and Future Enhancements

### Current Limitations

1. **Basic Parsing**: Response parsing is basic, can be enhanced with full protocol libraries
2. **SNMP**: Limited to basic detection, full ASN.1 parsing not implemented
3. **MQTT**: TCP-based, requires connection handling (currently basic)
4. **CoAP**: Link-Format parsing is basic
5. **mDNS**: DNS packet parsing is simplified

### Future Enhancements

1. **Full Protocol Parsing**:
   - Integrate `dns-parser` for complete mDNS parsing
   - Integrate `snmp-parser` for full SNMP support
   - Integrate `coap-lite` for complete CoAP support

2. **Additional Protocols**:
   - Modbus (industrial control)
   - BACnet (building automation)
   - KNX (home automation)
   - Zigbee discovery

3. **Enhanced Pivot Detection**:
   - Machine learning for pivot candidate scoring
   - Multi-factor pivot analysis
   - Pivot chain detection

4. **Performance Optimizations**:
   - Parallel probe sending
   - Adaptive timeout based on network latency
   - Probe deduplication

## Security Considerations

### Ethical Use

- **Authorized Testing Only**: IoT Spider should only be used on networks you own or have explicit permission to test
- **Network Impact**: Minimal, but still sends packets that may be logged
- **Device Impact**: Discovery probes are read-only, no authentication attempts

### Detection Avoidance

- **Multicast Protocols**: Less likely to trigger security alerts
- **No Connection Attempts**: Only sends discovery packets
- **Passive Capture**: Responses captured passively, no active connections

### Best Practices

1. **Use on Authorized Networks**: Only scan networks you have permission to test
2. **Respect Network Boundaries**: Multicast TTL limits prevent cross-network discovery
3. **Rate Limiting**: Built-in delays prevent network flooding
4. **Logging**: All probe activity is logged for audit trail

## Troubleshooting

### No Devices Discovered

**Possible Causes**:
- Network doesn't have IoT devices
- Firewall blocking multicast traffic
- Wrong network interface selected
- Devices not responding to probes

**Solutions**:
- Verify network interface: `Plan::with_interface("eth0")`
- Check firewall rules for multicast
- Try specific protocols: `vec!["ssdp".to_string()]`
- Increase timeout: `IoTProbeSource::with_timeout(Duration::from_secs(10))`

### Partial Discovery

**Possible Causes**:
- Some protocols not supported by devices
- Network segmentation limiting multicast
- Devices filtering specific protocols

**Solutions**:
- Try all protocols: `vec![]` (defaults to all)
- Use unicast probes for specific targets
- Check network topology for segmentation

### Performance Issues

**Possible Causes**:
- Too many targets for unicast probes
- Network latency affecting timeouts
- High packet capture load

**Solutions**:
- Use multicast-only for large networks
- Increase timeout for slow networks
- Limit protocols to essential ones

## Examples

### Example 1: Discover All IoT Devices

```rust
use crate::plan::Plan;
use uuid::Uuid;

let scan_id = Uuid::new_v4();
let plan = Plan::iot_spider(
    scan_id,
    "192.168.1.0/24".to_string(),
    vec![] // All protocols
)
.with_interface("eth0".to_string());

// Execute via engine
GLOBAL_ENGINE.execute(plan).await?;
```

### Example 2: Find Network Infrastructure

```rust
let plan = Plan::iot_spider(
    scan_id,
    "10.0.0.0/8".to_string(),
    vec!["snmp".to_string()]
)
.with_modules(vec!["vulnerability".to_string()]);
```

### Example 3: Stealth Discovery

```rust
// Use only multicast protocols (no direct connections)
let plan = Plan::iot_spider(
    scan_id,
    "192.168.1.0/24".to_string(),
    vec!["ssdp".to_string(), "mdns".to_string(), "wsdd".to_string()]
);
```

## Conclusion

IoT Spider provides a lightweight, efficient method for discovering IoT devices and identifying network pivot points. By combining active probing with passive monitoring, it offers a comprehensive view of network devices without the overhead of full port scans. Its integration with LEGION2's unified pipeline ensures that discovered devices are automatically enriched with MAC addresses, OS information, and vulnerability data, making it an essential tool for network reconnaissance and security assessment.

