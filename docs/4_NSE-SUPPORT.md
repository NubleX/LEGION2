# NSE Script Support in LEGION2

## Overview

LEGION2 supports Nmap Scripting Engine (NSE) scripts for enhanced vulnerability detection, service enumeration, and network reconnaissance. NSE scripts are automatically executed during nmap scans and their output is parsed and stored in the database.

## Features

- **Script Selection**: Specify which NSE scripts to run via Plan configuration
- **Script Arguments**: Pass arguments to scripts (e.g., `vuln.mincvss=7.0`)
- **Automatic Parsing**: Script output is automatically parsed from nmap XML
- **CVE Extraction**: CVE IDs are automatically extracted from script output
- **Database Integration**: Script results are stored with host/service associations

## Usage

### Basic Script Usage

```rust
use crate::plan::Plan;
use uuid::Uuid;

let scan_id = Uuid::new_v4();
let plan = Plan::nmap(
    scan_id,
    "192.168.1.0/24".to_string(),
    "1-1000".to_string(),
    vec!["-sV".to_string(), "-T4".to_string()]
)
.with_nse_scripts(vec!["vuln".to_string()]);
```

### Multiple Scripts

```rust
let plan = Plan::nmap(scan_id, targets, ports, extra_args)
    .with_nse_scripts(vec![
        "vuln".to_string(),
        "http-title".to_string(),
        "http-headers".to_string(),
        "ssh-hostkey".to_string()
    ]);
```

### Scripts with Arguments

```rust
use std::collections::HashMap;

let plan = Plan::nmap(scan_id, targets, ports, extra_args)
    .with_nse_scripts(vec!["vuln".to_string()])
    .with_nse_script_args({
        let mut args = HashMap::new();
        // Only show vulnerabilities with CVSS >= 7.0
        args.insert("vuln.mincvss".to_string(), "7.0".to_string());
        args
    });
```

### Combining with Other Options

```rust
let plan = Plan::comprehensive(scan_id, targets, ports)
    .with_nse_scripts(vec!["vuln".to_string()])
    .with_os_detection();
```

## Implementation Details

### Plan Structure

The `Plan` struct includes two new optional fields:

```rust
pub struct Plan {
    // ... existing fields ...
    pub nse_scripts: Option<Vec<String>>,
    pub nse_script_args: Option<HashMap<String, String>>,
}
```

### Nmap Command Building

The `NmapScanner::build_nmap_command()` method automatically adds NSE script flags:

```rust
// If scripts are specified:
if let Some(ref scripts) = plan.nse_scripts {
    if !scripts.is_empty() {
        let script_list = scripts.join(",");
        cmd.arg("--script").arg(&script_list);
    }
}

// If script arguments are specified:
if let Some(ref script_args) = plan.nse_script_args {
    if !script_args.is_empty() {
        let args_list: Vec<String> = script_args
            .iter()
            .map(|(key, value)| format!("{}={}", key, value))
            .collect();
        let args_string = args_list.join(",");
        cmd.arg("--script-args").arg(&args_string);
    }
}
```

### XML Parsing

Script output is automatically parsed from nmap XML by `XmlParser::create_script_observation()`:

- Extracts script ID from `<script id="...">` attribute
- Extracts script output from `output` attribute
- Parses script elements (key-value pairs) from `<elem>` children
- Extracts CVE IDs using regex pattern matching

## Common NSE Scripts

### Vulnerability Detection

**vuln**: Comprehensive vulnerability detection
```rust
.with_nse_scripts(vec!["vuln".to_string()])
.with_nse_script_args({
    let mut args = HashMap::new();
    args.insert("vuln.mincvss".to_string(), "7.0".to_string());
    args
})
```

**ssl-heartbleed**: Heartbleed vulnerability detection
```rust
.with_nse_scripts(vec!["ssl-heartbleed".to_string()])
```

**smb-vuln-ms17-010**: EternalBlue vulnerability detection
```rust
.with_nse_scripts(vec!["smb-vuln-ms17-010".to_string()])
```

### HTTP Service Enumeration

**http-title**: Extract HTTP page titles
```rust
.with_nse_scripts(vec!["http-title".to_string()])
```

**http-headers**: Extract HTTP headers
```rust
.with_nse_scripts(vec!["http-headers".to_string()])
```

**http-enum**: HTTP directory enumeration
```rust
.with_nse_scripts(vec!["http-enum".to_string()])
.with_nse_script_args({
    let mut args = HashMap::new();
    args.insert("http-enum.displayall".to_string(), "true".to_string());
    args
})
```

### Service-Specific Scripts

**ssh-hostkey**: SSH host key fingerprinting
```rust
.with_nse_scripts(vec!["ssh-hostkey".to_string()])
```

**snmp-info**: SNMP information gathering
```rust
.with_nse_scripts(vec!["snmp-info".to_string()])
.with_nse_script_args({
    let mut args = HashMap::new();
    args.insert("snmp.community".to_string(), "public".to_string());
    args
})
```

**ftp-anon**: FTP anonymous login detection
```rust
.with_nse_scripts(vec!["ftp-anon".to_string()])
```

## Script Output Format

### Observation Structure

Script observations are created with the following structure:

```json
{
  "kind": "Script",
  "key": "script-192.168.1.100-vuln",
  "fields": {
    "ip": "192.168.1.100",
    "port": "443",
    "protocol": "tcp",
    "script_id": "vuln",
    "script_output": "CVE-2021-44228: Apache Log4j 2.x before 2.15.0...",
    "script_elements": {
      "cve": "CVE-2021-44228",
      "severity": "critical",
      "cvss": "10.0",
      "title": "Apache Log4j Remote Code Execution"
    },
    "cve_ids": "CVE-2021-44228"
  },
  "raw": "CVE-2021-44228: Apache Log4j 2.x before 2.15.0..."
}
```

### Script Elements

Script elements are parsed from structured output in nmap XML:

```xml
<script id="vuln" output="...">
  <elem key="cve">CVE-2021-44228</elem>
  <elem key="severity">critical</elem>
  <elem key="cvss">10.0</elem>
</script>
```

These are automatically converted to JSON key-value pairs in the observation.

## Integration with Pipeline

### Observation Flow

```
NmapScanner executes nmap with --script flags
    ↓
Nmap generates XML output with <script> elements
    ↓
XmlParser::parse_nmap_xml() extracts script data
    ↓
XmlParser::create_script_observation() creates Script observations
    ↓
Observations flow through pipeline
    ├─ Transforms: Enrich with CVE data, vulnerability analysis
    ├─ UiSink: Display script results in frontend
    └─ DbSink: Store script results in database
```

### Database Storage

Script observations are stored in the database with:

- **Host association**: Linked to the host IP address
- **Service association**: Linked to the port/protocol (if port-specific)
- **CVE mapping**: CVE IDs extracted and linked to vulnerability records
- **Raw output**: Full script output preserved for reference

## Examples

### Example 1: Vulnerability Scan

```rust
use crate::plan::Plan;
use std::collections::HashMap;
use uuid::Uuid;

let scan_id = Uuid::new_v4();
let plan = Plan::nmap(
    scan_id,
    "192.168.1.0/24".to_string(),
    "1-1000".to_string(),
    vec!["-sV".to_string(), "-T4".to_string()]
)
.with_nse_scripts(vec!["vuln".to_string()])
.with_nse_script_args({
    let mut args = HashMap::new();
    args.insert("vuln.mincvss".to_string(), "7.0".to_string());
    args
});
```

### Example 2: HTTP Service Enumeration

```rust
let plan = Plan::nmap(
    scan_id,
    targets,
    "80,443,8080,8443".to_string(),
    vec!["-sV".to_string()]
)
.with_nse_scripts(vec![
    "http-title".to_string(),
    "http-headers".to_string(),
    "http-enum".to_string()
]);
```

### Example 3: Comprehensive Security Assessment

```rust
let plan = Plan::comprehensive(scan_id, targets, ports)
    .with_nse_scripts(vec![
        "vuln".to_string(),
        "ssl-heartbleed".to_string(),
        "smb-vuln-ms17-010".to_string(),
        "ssh-hostkey".to_string()
    ])
    .with_nse_script_args({
        let mut args = HashMap::new();
        args.insert("vuln.mincvss".to_string(), "5.0".to_string());
        args
    });
```

## Best Practices

1. **Script Selection**: Choose scripts relevant to your scan targets (e.g., `http-*` for web servers)
2. **Performance**: Running many scripts can slow down scans - use selectively
3. **Arguments**: Use script arguments to filter results and reduce noise
4. **CVSS Filtering**: Use `vuln.mincvss` to focus on high-severity vulnerabilities
5. **Combination**: Combine NSE scripts with service detection (`-sV`) for best results

## Troubleshooting

### Scripts Not Running

**Possible Causes**:
- Scripts not installed in nmap scripts directory
- Script names misspelled
- Scripts require specific ports to be open

**Solutions**:
- Verify script names: `nmap --script-help <script-name>`
- Check nmap script directory: `/usr/share/nmap/scripts/`
- Update script database: `nmap --script-updatedb`

### Script Output Not Appearing

**Possible Causes**:
- Scripts ran but found nothing
- XML parsing issues
- Script output format not recognized

**Solutions**:
- Check nmap XML output for `<script>` elements
- Verify XML parser is handling script elements correctly
- Check logs for parsing errors

### Performance Issues

**Possible Causes**:
- Too many scripts running
- Scripts taking too long to execute
- Network latency

**Solutions**:
- Reduce number of scripts
- Use script categories (e.g., `vuln` instead of individual scripts)
- Increase scan timeout if needed

## References

- [Nmap NSE Documentation](https://nmap.org/book/nse.html)
- [NSE Script Database](https://nmap.org/nsedoc/)
- [LEGION2 Plan Documentation](./MASSMAP.md)
- [XML Parsing Documentation](./XML-parsing.md)

