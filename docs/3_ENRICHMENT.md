# Network Enrichment in LEGION2

## Overview

LEGION2 employs a comprehensive enrichment pipeline that transforms raw network observations into a rich, actionable knowledgebase. Enrichment occurs at multiple stages of the scanning pipeline, leveraging passive monitoring, active probing, protocol analysis, and external databases to build a complete picture of the target network.

## Enrichment Architecture

Enrichment in LEGION2 follows a **transform-based pipeline** architecture where observations flow through specialized enrichment modules:

```
Raw Observations (from Sources)
    ↓
┌─────────────────────────────────────┐
│      Transform Pipeline              │
│  (Enrichment Modules)                │
├─────────────────────────────────────┤
│ 1. MAC-Vendor Enrichment            │
│ 2. OS Fingerprinting                 │
│ 3. Service Parsing                   │
│ 4. CVE/Exploit Enrichment            │
│ 5. Port-Service-CVE Correlation     │
│ 6. IoT Protocol Analysis             │
│ 7. Access Point Discovery            │
└─────────────────────────────────────┘
    ↓
Enriched Observations
    ↓
┌─────────────────────────────────────┐
│      Knowledgebase (Database)        │
│  - Hosts with MAC/Vendor/OS          │
│  - Services with CVE mappings        │
│  - Port-Service-CVE relationships    │
│  - IoT device inventory              │
│  - Access point topology             │
└─────────────────────────────────────┘
```

## Types of Enrichment

### 1. MAC-Vendor Enrichment

**Purpose**: Identify device manufacturers and vendors from MAC addresses using OUI (Organizationally Unique Identifier) lookups.

**How It Works**:
- Extracts MAC addresses from Ethernet headers (Layer 2)
- Parses first 3 bytes (OUI) from MAC address
- Queries comprehensive OUI database (`netsniffer::oui_lookup_vendor()`)
- Stores vendor information in database

**Implementation**:
- **Transform**: `MacEnrichmentTransform`
- **Module Name**: `mac_enrichment` or `mac-enrichment`
- **Database Fields**: `nic_vendor`, `vendor`, `mac_address`

**Example**:
```rust
// MAC address: 00:1B:63:AA:BB:CC
// OUI: 00:1B:63 → "Apple, Inc."
// Stored in database:
{
    "ip": "192.168.1.100",
    "mac_address": "00:1B:63:AA:BB:CC",
    "nic_vendor": "Apple, Inc.",
    "vendor": "Apple, Inc."
}
```

**Use Cases**:
- Identify device types (routers, IoT devices, workstations)
- Correlate MAC addresses across multiple IPs (DHCP lease tracking)
- Detect virtual machines (VMware, VirtualBox, Hyper-V)
- Network topology mapping

**Supported Vendors**:
- Major manufacturers: Apple, Microsoft, Cisco, Dell, HP, Intel
- Virtualization: VMware, VirtualBox, Parallels, Hyper-V
- Networking: Netgear, Linksys, TP-Link, D-Link
- IoT: Raspberry Pi, Samsung, Arris

### 2. OS Fingerprinting

**Purpose**: Detect operating systems and versions using passive network fingerprinting techniques.

**Methods**:

#### A. TTL-Based Detection
- **TTL 64**: Linux/Unix systems
- **TTL 128**: Windows systems
- **TTL 255**: Network devices/routers
- **TTL 32**: Some Unix variants

#### B. TCP Signature Analysis
- **Window Size**: Different OSes use characteristic window sizes
  - Windows 7/8/10: 8192 bytes
  - Windows XP/2003: 65535 bytes
  - Linux 2.6.x: 5840 bytes
  - Linux 3.x/4.x: 29200 bytes
  - macOS/BSD: 65535 bytes
- **TCP Options**: MSS, Window Scaling, SACK, Timestamps
- **Options Hash**: Unique fingerprint from TCP options sequence

**Implementation**:
- **Transform**: `PassiveOsTransform`
- **Module Name**: `passive_os` or `passive-os`
- **Database Fields**: `os_name`, `os_family`, `os_accuracy`

**Confidence Scoring**:
- Base score: 0-100
- TTL match: +20 points
- TCP window match: +30 points
- MSS match: +20 points
- Window scale match: +15 points
- SACK support: +15 points

**Example**:
```rust
// Detected from packet:
{
    "ttl": 64,
    "tcp_window": 29200,
    "tcp_mss": 1460,
    "tcp_wscale": 7,
    "tcp_sack_ok": true
}
// Result:
{
    "os_name": "Linux 3.x/4.x",
    "os_family": "Linux",
    "os_accuracy": 100.0,
    "os_detection_method": "passive_tcp_signature"
}
```

**Use Cases**:
- Identify vulnerable OS versions
- Correlate OS with CVE database
- Network segmentation planning
- Compliance auditing

### 3. CVE/Exploit Enrichment

**Purpose**: Automatically identify known vulnerabilities and exploits for discovered services and products.

**How It Works**:
1. Extracts product/version information from service observations
2. Queries CVE database (`cve_db.rs`) for matching CVEs
3. Queries ExploitDB for associated exploits
4. Stores CVEs and exploits in respective databases
5. Emits vulnerability observations with severity and exploit information

**Implementation**:
- **Transform**: `CveExploitEnrichmentTransform`
- **Module Name**: `cve_enrichment` or `cve-enrichment`
- **Database**: Separate CVE database (`cve_db.rs`)

**Data Sources**:
- **CVE Database**: Local SQLite database with NVD (National Vulnerability Database) data
- **ExploitDB**: Offensive Security Exploit Database
- **CVSS Scores**: Vulnerability severity ratings (0.0-10.0)

**Example**:
```rust
// Service observation:
{
    "ip": "192.168.1.50",
    "port": 22,
    "service": "ssh",
    "product": "OpenSSH",
    "version": "7.4"
}
// CVE enrichment finds:
{
    "cve_id": "CVE-2017-15906",
    "severity": "high",
    "cvss_score": 7.5,
    "product": "OpenSSH",
    "version": "7.4",
    "description": "OpenSSH before 7.4 allows remote...",
    "exploit_id": "43124",
    "exploit_url": "https://www.exploit-db.com/exploits/43124"
}
```

**Use Cases**:
- Automated vulnerability assessment
- Risk prioritization (CVSS scores)
- Exploit availability checking
- Compliance reporting

### 4. Port-Service-CVE Correlation

**Purpose**: Build relationships between ports, services, and known vulnerabilities to enable predictive vulnerability detection.

**How It Works**:
1. Identifies port-service combinations from observations
2. Queries CVE database for common vulnerabilities on specific port/service pairs
3. Creates port-service-CVE mapping keys
4. Stores correlations for future lookups

**Implementation**:
- **Transform**: `PortServiceCveTransform`
- **Module Name**: `port_service_cve` or `port-service-cve`
- **Database**: Port-service-CVE relationships stored in observations

**Example**:
```rust
// Port-service observation:
{
    "ip": "192.168.1.100",
    "port": 3306,
    "service": "mysql",
    "protocol": "tcp"
}
// Correlation creates:
{
    "port_service_key": "3306-mysql",
    "needs_cve_check": true,
    // CVE enrichment will query for MySQL CVEs
}
```

**Common Port-Service-CVE Mappings**:
- **Port 22 (SSH)**: OpenSSH vulnerabilities
- **Port 80/443 (HTTP/HTTPS)**: Web server CVEs (Apache, nginx, IIS)
- **Port 3306 (MySQL)**: Database vulnerabilities
- **Port 3389 (RDP)**: Remote desktop vulnerabilities
- **Port 21 (FTP)**: FTP server vulnerabilities

**Use Cases**:
- Predictive vulnerability detection
- Service-specific CVE lookup
- Risk assessment by port
- Security policy enforcement

## IoT Traffic Enrichment

### Overview

IoT devices use specialized protocols for discovery and communication. LEGION2 can passively monitor and actively probe these protocols to discover and enrich IoT device information.

### Supported IoT Protocols

#### 1. SSDP/UPnP (Simple Service Discovery Protocol)

**Port**: 1900 UDP (multicast)  
**Multicast Address**: 239.255.255.250  
**Purpose**: Universal Plug and Play device discovery

**Enrichment Capabilities**:
- Device identification from LOCATION header
- Firmware version from SERVER header
- Device type from USN (Unique Service Name)
- Service endpoints from LOCATION URL

**Implementation**:
- **Probe**: `SSDPProbe` (`scanners/probes/iot_probes.rs`)
- **Passive Detection**: NetSniffer captures SSDP M-SEARCH responses
- **Active Probing**: `IoTProbeSender::send_multicast_probe(IoTProtocol::SSDP)`

**Example Enrichment**:
```rust
// SSDP response captured:
LOCATION: http://192.168.1.50:49152/description.xml
SERVER: Linux/3.14 UPnP/1.0 SmartTV/1.0
USN: uuid:12345678-1234-1234-1234-123456789012::upnp:rootdevice
ST: upnp:rootdevice

// Enriched observation:
{
    "ip": "192.168.1.50",
    "device_type": "SmartTV",
    "os": "Linux 3.14",
    "upnp_location": "http://192.168.1.50:49152/description.xml",
    "device_uuid": "12345678-1234-1234-1234-123456789012",
    "protocol": "ssdp"
}
```

**Use Cases**:
- IoT device inventory
- Smart home device discovery
- Media server detection
- Router/access point discovery

#### 2. mDNS/DNS-SD (Multicast DNS)

**Port**: 5353 UDP (multicast)  
**Multicast Address**: 224.0.0.251  
**Purpose**: Zero-configuration networking (Bonjour, Avahi)

**Enrichment Capabilities**:
- Service discovery (_services._dns-sd._udp.local)
- Device hostnames (.local domain)
- Service types (HTTP, SSH, VNC, etc.)
- TXT record metadata

**Implementation**:
- **Probe**: `MDNSProbe` (`scanners/probes/iot_probes.rs`)
- **Passive Detection**: NetSniffer captures mDNS responses
- **Active Probing**: `IoTProbeSender::send_multicast_probe(IoTProtocol::MDNS)`

**Example Enrichment**:
```rust
// mDNS response:
_http._tcp.local → MyPrinter._http._tcp.local
TXT: model=HP LaserJet, serial=ABC123

// Enriched observation:
{
    "ip": "192.168.1.200",
    "hostname": "MyPrinter.local",
    "service": "http",
    "device_type": "printer",
    "manufacturer": "HP",
    "model": "LaserJet",
    "serial": "ABC123",
    "protocol": "mdns"
}
```

**Use Cases**:
- Printer discovery
- Apple device detection (AirPlay, AirPrint)
- IoT device identification
- Service enumeration

#### 3. CoAP (Constrained Application Protocol)

**Port**: 5683 UDP (multicast)  
**Multicast Address**: 224.0.1.187  
**Purpose**: Lightweight IoT communication protocol

**Enrichment Capabilities**:
- Resource discovery (/.well-known/core)
- Device capabilities
- Resource endpoints
- Link-Format parsing

**Implementation**:
- **Probe**: `CoAPProbe` (`scanners/probes/iot_probes.rs`)
- **Passive Detection**: NetSniffer captures CoAP responses
- **Active Probing**: `IoTProbeSender::send_multicast_probe(IoTProtocol::CoAP)`

**Example Enrichment**:
```rust
// CoAP response from /.well-known/core:
</sensors/temp>;ct=0;rt="temperature-c",
</sensors/humidity>;ct=0;rt="humidity",
</actuators/led>;ct=0;if="actuator"

// Enriched observation:
{
    "ip": "192.168.1.150",
    "protocol": "coap",
    "resources": [
        {"path": "/sensors/temp", "type": "temperature-c"},
        {"path": "/sensors/humidity", "type": "humidity"},
        {"path": "/actuators/led", "type": "actuator"}
    ],
    "device_type": "iot_sensor"
}
```

**Use Cases**:
- IoT sensor discovery
- Smart home device enumeration
- Resource endpoint mapping
- Device capability assessment

#### 4. MQTT (Message Queuing Telemetry Transport)

**Port**: 1883 TCP (standard), 8883 TCP (TLS)  
**Purpose**: IoT messaging protocol

**Enrichment Capabilities**:
- Broker discovery
- Topic enumeration
- Authentication status
- Client identification

**Implementation**:
- **Probe**: `MQTTProbe` (`scanners/probes/iot_probes.rs`)
- **Active Probing**: `IoTProbeSender::send_unicast_probe(IoTProtocol::MQTT, target_ip)`

**Example Enrichment**:
```rust
// MQTT CONNACK response:
Return Code: 0 (Connection Accepted)

// Enriched observation:
{
    "ip": "192.168.1.100",
    "port": 1883,
    "service": "mqtt",
    "protocol": "mqtt",
    "broker_status": "active",
    "authentication": "none"
}
```

**Use Cases**:
- IoT broker discovery
- Message queue enumeration
- Device communication analysis
- Security assessment (unauthenticated brokers)

#### 5. SNMP (Simple Network Management Protocol)

**Port**: 161 UDP  
**Purpose**: Network device management

**Enrichment Capabilities**:
- System description (sysDescr OID: 1.3.6.1.2.1.1.1.0)
- Device identification
- Firmware versions
- Community string enumeration

**Implementation**:
- **Probe**: `SNMPProbe` (`scanners/probes/iot_probes.rs`)
- **Active Probing**: `IoTProbeSender::send_unicast_probe(IoTProtocol::SNMP, target_ip)`

**Example Enrichment**:
```rust
// SNMP response:
sysDescr: "Cisco IOS Software, C2960 Software (C2960-LANBASE-M), Version 15.0(2)SE"

// Enriched observation:
{
    "ip": "192.168.1.1",
    "port": 161,
    "service": "snmp",
    "device_type": "switch",
    "manufacturer": "Cisco",
    "model": "C2960",
    "firmware": "15.0(2)SE",
    "protocol": "snmp"
}
```

**Use Cases**:
- Network device inventory
- Firmware version detection
- Community string enumeration
- Device management interface discovery

#### 6. WSDD (Web Services Dynamic Discovery)

**Port**: 3702 UDP (multicast)  
**Multicast Address**: 239.255.255.250  
**Purpose**: Windows device discovery

**Enrichment Capabilities**:
- Windows device identification
- Service endpoints (XAddrs)
- Device types
- SOAP service enumeration

**Implementation**:
- **Probe**: `WSDDProbe` (`scanners/probes/iot_probes.rs`)
- **Passive Detection**: NetSniffer captures WSDD responses
- **Active Probing**: `IoTProbeSender::send_multicast_probe(IoTProtocol::WSDD)`

**Example Enrichment**:
```rust
// WSDD ProbeMatch response:
XAddrs: http://192.168.1.100:5357/onvif/device_service
Types: wsdp:Device

// Enriched observation:
{
    "ip": "192.168.1.100",
    "protocol": "wsdd",
    "device_type": "onvif_camera",
    "service_endpoints": ["http://192.168.1.100:5357/onvif/device_service"]
}
```

**Use Cases**:
- Windows device discovery
- ONVIF camera detection
- Network printer discovery
- Windows service enumeration

### IoT Enrichment Workflow

**Passive Monitoring** (NetSniffer):
```
1. NetSniffer captures packets on network interface
2. Filters for IoT protocol traffic (SSDP, mDNS, CoAP)
3. Parses protocol-specific responses
4. Extracts device information
5. Enriches host observations with IoT data
```

**Active Probing** (IoT Probes):
```
1. Send multicast probes (SSDP, mDNS, CoAP, WSDD)
2. Send unicast probes (SNMP, MQTT)
3. Capture responses
4. Parse protocol-specific data
5. Create enriched observations
```

**Integration Example**:
```rust
// In NetSnifferSource or custom transform:
if packet.dport == 1900 && packet.proto == "udp" {
    // SSDP response detected
    if let Ok(ssdp_response) = SSDPProbe::parse_response(&packet.data) {
        // Enrich host observation
        host_obs.fields.insert("device_type", "iot_device");
        host_obs.fields.insert("upnp_location", ssdp_response.device_info["location"]);
        host_obs.fields.insert("protocol", "ssdp");
    }
}
```

## Access Point Enrichment

### Overview

WiFi access points and wireless networks provide rich metadata for network enrichment, including SSID, BSSID, encryption types, signal strength, and client associations.

### WiFi Protocol Support

**802.11 Frame Types**:
- **Beacon Frames**: Access point advertisements
- **Probe Requests**: Client device discovery
- **Probe Responses**: Access point responses
- **Association Requests**: Client connection attempts

### Enrichment Capabilities

#### 1. Access Point Discovery

**Information Extracted**:
- **SSID**: Network name
- **BSSID**: Access point MAC address
- **Channel**: Operating frequency channel
- **Encryption**: WPA2, WPA3, WEP, Open
- **Signal Strength**: RSSI (Received Signal Strength Indicator)
- **Vendor**: From BSSID OUI lookup
- **Security**: Authentication methods

**Example Enrichment**:
```rust
// Beacon frame captured:
SSID: "Corporate_WiFi"
BSSID: 00:11:22:33:44:55
Channel: 6
Encryption: WPA2-Enterprise
RSSI: -45 dBm

// Enriched observation:
{
    "observation_type": "access_point",
    "ssid": "Corporate_WiFi",
    "bssid": "00:11:22:33:44:55",
    "channel": 6,
    "encryption": "WPA2-Enterprise",
    "rssi": -45,
    "vendor": "Cisco Systems",
    "security_type": "enterprise"
}
```

#### 2. Client Device Discovery

**Information Extracted**:
- **Client MAC**: Device MAC address
- **Probed SSIDs**: Networks device is looking for
- **Vendor**: From MAC OUI lookup
- **Device Type**: Inferred from probe patterns

**Example Enrichment**:
```rust
// Probe request captured:
Source MAC: AA:BB:CC:DD:EE:FF
Probed SSID: "Guest_WiFi"

// Enriched observation:
{
    "observation_type": "client_device",
    "mac_address": "AA:BB:CC:DD:EE:FF",
    "vendor": "Apple, Inc.",
    "probed_networks": ["Guest_WiFi"],
    "device_type": "mobile_device"
}
```

#### 3. Network Topology Mapping

**Capabilities**:
- Access point to client associations
- Signal strength mapping
- Channel interference analysis
- Rogue access point detection

**Example Enrichment**:
```rust
// Association relationship:
{
    "access_point": {
        "bssid": "00:11:22:33:44:55",
        "ssid": "Corporate_WiFi"
    },
    "clients": [
        {"mac": "AA:BB:CC:DD:EE:FF", "rssi": -50},
        {"mac": "11:22:33:44:55:66", "rssi": -65}
    ],
    "topology_type": "wireless_association"
}
```

### Implementation Notes

**Current Status**:
- WiFi frame parsing is planned but not yet fully implemented
- Requires 802.11 packet capture (monitor mode)
- Platform-specific (Linux: monitor mode, macOS: airport, Windows: netsh)

**Future Enhancements**:
- 802.11 beacon frame parsing
- Probe request/response analysis
- WPA handshake capture
- Signal strength mapping
- Channel analysis

## Protocol-Based Enrichment

### Overview

Different network protocols provide unique enrichment opportunities. LEGION2 analyzes protocol-specific characteristics to extract maximum intelligence.

### Protocol Categories

#### 1. Discovery Protocols

**SSDP/UPnP**: Device and service discovery
- LOCATION URLs for device description
- SERVER headers for OS/firmware
- USN for device identification

**mDNS/DNS-SD**: Zero-configuration networking
- Service enumeration
- Hostname resolution (.local)
- TXT record metadata

**LLMNR**: Windows name resolution
- Hostname discovery
- Windows domain identification

**NetBIOS**: Windows network discovery
- Computer names
- Workgroup/domain names
- Service enumeration

#### 2. Management Protocols

**SNMP**: Network device management
- System information (sysDescr)
- Device identification
- Firmware versions
- Community strings

**DHCP**: IP address assignment
- Hostname discovery
- Vendor class identifiers
- Option 12 (hostname)
- Option 43 (vendor-specific)

**ICMP**: Network diagnostics
- Host discovery
- OS fingerprinting (TTL)
- Network topology (traceroute)

#### 3. Application Protocols

**HTTP/HTTPS**: Web services
- Server headers (Apache, nginx, IIS)
- Application frameworks
- Version information
- Security headers

**SSH**: Remote access
- Banner grabbing
- Version detection
- Key exchange algorithms

**FTP**: File transfer
- Banner analysis
- Anonymous access detection
- Version identification

**SMTP**: Email services
- Server identification
- Banner analysis
- Authentication methods

#### 4. IoT Protocols

**MQTT**: IoT messaging
- Broker identification
- Topic enumeration
- Authentication status

**CoAP**: Constrained applications
- Resource discovery
- Device capabilities
- Endpoint mapping

**Modbus**: Industrial control
- Device identification
- Function code enumeration
- Unit ID discovery

### Protocol Enrichment Transform

**Future Implementation**:
A `ProtocolEnrichmentTransform` could:
- Parse protocol-specific headers
- Extract version information
- Identify application frameworks
- Detect security configurations
- Map protocol features

**Example**:
```rust
// HTTP response:
HTTP/1.1 200 OK
Server: nginx/1.18.0
X-Powered-By: PHP/7.4.3

// Enriched observation:
{
    "ip": "192.168.1.100",
    "port": 80,
    "service": "http",
    "product": "nginx",
    "version": "1.18.0",
    "application": "PHP",
    "app_version": "7.4.3"
}
```

## Enrichment Pipeline Configuration

### Default NetSniffer Enrichment

When using `Plan::netsniffer()`, the following enrichment modules are automatically applied:

```rust
modules: vec![
    "mac_enrichment",      // MAC-vendor lookup
    "passive_os",          // OS fingerprinting
    "service_parsing",     // Service identification
    "cve_enrichment",      // CVE/Exploit lookup
    "port_service_cve",    // Port-service-CVE correlation
]
```

### Custom Enrichment Pipeline

You can customize the enrichment pipeline by specifying modules:

```rust
let plan = Plan::netsniffer(scan_id, "eth0")
    .with_modules(vec![
        "mac_enrichment",
        "passive_os",
        "cve_enrichment",
    ]);
```

### Available Enrichment Modules

| Module Name | Description | Output Fields |
|------------|-------------|---------------|
| `mac_enrichment` | MAC-vendor lookup | `vendor`, `nic_vendor`, `oui` |
| `passive_os` | OS fingerprinting | `os_name`, `os_family`, `os_accuracy` |
| `service_parsing` | Service identification | `service`, `product`, `version` |
| `cve_enrichment` | CVE/Exploit lookup | `cve_id`, `severity`, `exploit_id` |
| `port_service_cve` | Port-service-CVE correlation | `port_service_key`, `needs_cve_check` |
| `ip_enrichment` | IP normalization | `extracted_ips` |
| `progress_tracking` | Scan progress | `progress_percent` |

## Database Storage

### Host Enrichment Storage

Enriched host data is stored in the `hosts` table:

```sql
CREATE TABLE hosts (
    id TEXT PRIMARY KEY,
    ip_encrypted TEXT UNIQUE NOT NULL,
    hostname TEXT,
    mac_address TEXT,          -- Encrypted MAC
    vendor TEXT,               -- General vendor
    nic_vendor TEXT,           -- NIC vendor from OUI
    nic_model TEXT,            -- NIC model
    os_name TEXT,              -- Detected OS
    os_family TEXT,            -- OS family
    os_accuracy REAL,          -- Confidence score (0-100)
    status TEXT,
    ...
);
```

### Service Enrichment Storage

Enriched service data is stored in the `ports` table:

```sql
CREATE TABLE ports (
    id TEXT PRIMARY KEY,
    host_id TEXT NOT NULL,
    number INTEGER NOT NULL,
    protocol TEXT NOT NULL,
    service_name TEXT,         -- Service identification
    product TEXT,               -- Product name
    version TEXT,               -- Version information
    banner TEXT,                -- Service banner
    ...
);
```

### CVE Storage

CVEs are stored in a separate database (`cve_db.rs`):

```sql
CREATE TABLE cves (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    product TEXT NOT NULL,
    version TEXT NOT NULL,
    severity TEXT NOT NULL,
    cvss_score REAL,
    exploit_id TEXT,
    exploit_url TEXT,
    ...
);
```

### Vulnerability Storage

Vulnerabilities are linked to hosts and ports:

```sql
CREATE TABLE vulnerabilities (
    id TEXT PRIMARY KEY,
    host_id TEXT NOT NULL,
    port_id TEXT,
    name TEXT NOT NULL,
    severity TEXT NOT NULL,
    cve TEXT,
    cvss_score REAL,
    ...
);
```

## Usage Examples

### Example 1: Basic NetSniffer Enrichment

```rust
// Create netsniffer plan with default enrichment
let plan = Plan::netsniffer(scan_id, "eth0");

// Execute via engine
engine.execute(plan).await?;

// Enrichment happens automatically:
// 1. MAC addresses → Vendor lookup
// 2. TTL/TCP signatures → OS detection
// 3. Ports → Service identification
// 4. Services → CVE lookup
// 5. Results stored in database
```

### Example 2: IoT Device Discovery

```rust
// Send SSDP probe
IoTProbeSender::send_multicast_probe(
    &IoTProtocol::SSDP,
    Some("eth0")
)?;

// NetSniffer captures responses
// SSDPProbe::parse_response() extracts:
// - Device type
// - Firmware version
// - Service endpoints
// - Device UUID

// Enriched observations stored in database
```

### Example 3: Custom Enrichment Pipeline

```rust
// Create plan with specific enrichment modules
let plan = Plan::netsniffer(scan_id, "eth0")
    .with_modules(vec![
        "mac_enrichment",      // Only MAC-vendor
        "passive_os",          // Only OS detection
        // Skip CVE enrichment for faster processing
    ]);

engine.execute(plan).await?;
```

### Example 4: Access Point Enrichment (Future)

```rust
// Capture WiFi beacons
// Parse 802.11 frames
// Extract:
// - SSID
// - BSSID (MAC)
// - Encryption type
// - Signal strength
// - Vendor from BSSID OUI

// Store in database:
db.store_access_point(
    bssid: "00:11:22:33:44:55",
    ssid: "Corporate_WiFi",
    encryption: "WPA2-Enterprise",
    vendor: "Cisco Systems",
    channel: 6,
    rssi: -45
)?;
```

## Best Practices

### 1. Enrichment Order

Apply enrichment modules in logical order:
1. **MAC enrichment** first (foundation data)
2. **OS fingerprinting** (uses MAC vendor hints)
3. **Service parsing** (identifies products)
4. **CVE enrichment** (requires product/version)
5. **Port-service-CVE correlation** (final step)

### 2. Performance Considerations

- **CVE enrichment** can be slow (database queries)
- Use selectively on high-value targets
- Cache CVE lookups to avoid duplicate queries
- Batch database operations

### 3. Accuracy vs Speed

- **Passive OS detection**: Fast but lower accuracy (60-80%)
- **Active OS detection** (nmap -O): Slower but higher accuracy (90%+)
- Combine both for best results

### 4. IoT Device Discovery

- **Passive monitoring**: Low overhead, discovers active devices
- **Active probing**: Higher overhead, discovers all devices
- Use passive monitoring first, then targeted active probes

### 5. Database Maintenance

- CVE database should be updated regularly
- ExploitDB should be synced periodically
- OUI database is static but can be extended
- Clean up stale observations periodically

## Integration with Other Components

### NetSniffer Integration

NetSniffer automatically applies enrichment transforms:
- Captures packets → Extracts MAC/IP/Port data
- MAC enrichment → Vendor identification
- OS fingerprinting → OS detection
- Service parsing → Service identification
- CVE enrichment → Vulnerability detection

### Massmap Integration

Massmap results can be enriched post-scan:
- Nmap XML output → Service/product/version
- CVE enrichment → Vulnerability lookup
- MAC enrichment → Vendor identification (if MACs in XML)

### Vulnerability Analysis Integration

Enriched observations feed into vulnerability analysis:
- CVE data → Risk scoring
- Exploit availability → Exploitability assessment
- Port-service-CVE → Common vulnerability patterns

## Future Enhancements

### Planned Features

1. **Geo-Location Enrichment**
   - ASN lookup for IP addresses
   - Country/region identification
   - ISP information

2. **Protocol Deep Inspection**
   - HTTP header analysis
   - TLS/SSL certificate parsing
   - DNS query analysis
   - DHCP option parsing

3. **Access Point Full Support**
   - 802.11 frame parsing
   - WPA handshake capture
   - Signal strength mapping
   - Channel interference analysis

4. **IoT Device Fingerprinting**
   - Device model identification
   - Firmware version detection
   - Vulnerability mapping

5. **Network Topology**
   - Host-to-host communication mapping
   - Network graph construction
   - Path analysis

6. **Threat Intelligence**
   - Integration with threat feeds
   - Known malicious IP detection
   - Reputation scoring

## Conclusion

LEGION2's enrichment pipeline transforms raw network observations into a comprehensive knowledgebase. By combining passive monitoring, active probing, protocol analysis, and external databases, the system builds a detailed picture of the target network.

The enrichment system is modular and extensible, allowing new enrichment types to be added as transforms. Current enrichments include MAC-vendor mapping, OS fingerprinting, CVE/exploit correlation, and IoT device discovery, with access point and protocol-specific enrichments planned for future releases.

All enriched data flows through the unified pipeline architecture, ensuring consistent storage in the encrypted database and real-time updates to the frontend via Tauri events.

