# LEGION2 XML Pipeline Architecture Redesign

## Overview

Redesign the scanning pipeline to have each scanner handle its own XML output parsing, with proper data flow through transforms → analysis → sinks. Both nmap and masscan will output XML (`-oX` flag) that gets parsed into comprehensive observations.

## Architecture Flow

```
Scanner → XML Parser → Raw Observations → Transforms → Enriched Observations → Analysis → Sinks
```

## 1. XML Storage & Queue Management

* **XML Files**: Store in `src-tauri/.scans/` directory with UUID names
* **Queue System**: Use filesystem-based queue for scan results awaiting processing
* **Cleanup**: Remove XML files after successful processing

## 2. Scanner Streams (`utils/`)

Create dedicated streaming modules.

### `utils/nmap_stream.rs`

* Use nmap with `-oX output.xml` + verbose stdout for progress
* Parse XML using legacy `Host.rs`, `Service.rs`, `Port.rs`, `Session.rs` parsers
* Emit comprehensive Host/Service/Port observations with all fields
* Handle nmap scripts and vulnerability detection

### `utils/masscan_stream.rs`

* Use masscan with `-oX output.xml` + real-time JSON output
* Parse XML for detailed service/banner information
* Create Service observations with enhanced data

## 3. Enhanced Transforms (`core/transforms.rs`)

Expand transforms to handle rich observation data.

### `IpEnrichmentTransform`

* Extract IPs, MACs, vendors from comprehensive host observations
* Add geolocation and network classification

### `ServiceParsingTransform`

* Parse service banners using `Service.rs` patterns
* Extract CPE identifiers and version information
* Map services to vulnerability databases

### `PortAnalysisTransform`

* Risk scoring using `Port.rs` utilities
* Common port classification
* Service fingerprinting

### `ScriptAnalysisTransform`

* Process nmap script results using `Script.rs`
* Parse Vulners/Shodan output for CVEs
* Extract vulnerability indicators

## 4. Analysis Pipeline (`analysis/`)

### `vulnerability.rs` Enhancement

* Integrate `CVE.rs` for vulnerability database queries
* Use `ExploitDb.rs` for exploit matching
* Cross-reference services with known vulnerabilities
* CVSS scoring and risk assessment

### New: `analysis/cve_engine.rs`

* CVE database management and querying
* ExploitDB integration for proof-of-concept lookups
* Automated vulnerability correlation

## 5. Enhanced Sinks (`core/sinks.rs`)

### `DbSink` Improvements

* Store comprehensive host data (MAC, vendor, OS, uptime, distance)
* Enhanced service storage with banners, CPE, confidence scores
* Vulnerability storage with CVE details and exploit references
* Script result storage

### `UiSink` Enhancements

* Emit detailed host events with all parsed fields
* Rich service events with version/banner information
* Vulnerability events with severity and exploit data
* Progress events with scan statistics

## 6. Data Models Integration

Integrate legacy parser structures.

### From `Host.rs`

* Comprehensive host information (MAC, vendor, hostname, OS, uptime, distance)
* Host classification and risk scoring

### From `Service.rs`

* Service fingerprinting and version detection
* CPE extraction and vulnerability indicators
* Service risk scoring and categorization

### From `Port.rs`

* Port state analysis and classification
* Service-to-port mapping
* Script result parsing

### From `CVE.rs` & `ExploitDb.rs`

* CVE database integration
* Exploit correlation and scoring
* Vulnerability assessment and reporting

## 7. Implementation Steps

### Phase 1: XML Parser Integration

1. Create `utils/xml_parsers.rs` with Host, Service, Port, Session structs
2. Implement comprehensive XML parsing methods
3. Update nmap/masscan scanners to output XML + progress

### Phase 2: Transform Enhancement

1. Expand transforms to handle rich observation data
2. Add script analysis and vulnerability parsing
3. Implement service fingerprinting and CPE extraction

### Phase 3: Analysis Engine

1. Integrate CVE database and ExploitDB
2. Implement vulnerability correlation engine
3. Add risk scoring and assessment

### Phase 4: Sink Improvements

1. Enhance database schema for comprehensive data
2. Update UI events for rich information display
3. Add vulnerability and exploit reporting

### Phase 5: Testing & Integration

1. End-to-end testing of XML → observations → UI flow
2. Verify all host fields are properly displayed
3. Test vulnerability detection and exploit correlation

## Benefits

* **Separation of Concerns**: Each scanner handles its own XML parsing
* **Rich Data Flow**: Comprehensive host/service/vulnerability information
* **Extensibility**: Easy to add new scanners and analysis modules
* **Performance**: Efficient batch processing and database operations
* **Completeness**: No more “unknown” fields — full data extraction

