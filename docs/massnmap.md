# Masscan & Nmap Advanced Command-Line Cheatsheet

---

## Masscan

Masscan is a lightning-fast port scanner, ideal for large-scale reconnaissance.

### Basic Syntax

```bash
masscan [options] [targets]
```

---

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

---

### Port Specification

```bash
masscan -p80
masscan -p20-100
masscan -p80,443,8080
masscan -p1-65535
```

---

### Rate & Performance

```bash
masscan --rate 1000           # Packets per second
masscan --rate 1000000        # Max rate
masscan --max-rate 50000      # Alias for --rate
masscan --min-rate 100        # Minimum rate
masscan --max-retries 2       # Retries per port
masscan --wait 10             # Wait for results (seconds)
```

---

### Output Options

```bash
masscan -oL results.txt       # List format
masscan -oX results.xml       # XML format
masscan -oB results.bin       # Binary format
masscan --output-format json  # JSON output (if supported)
```

---

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
```

---

### Example Advanced Commands

```bash
# Banner grab on top 1000 ports
masscan -p1-1000 --banners 192.168.1.0/24 --rate=500

# Save packets to PCAP for later analysis
masscan -p80 10.0.0.0/8 --pcap out.pcap

# Sharded scan for distributed scanning
masscan -p80 192.168.0.0/16 --shard 2/4 --rate=10000
```

---

## Nmap

Nmap is a versatile network scanner for discovery, enumeration, and vulnerability assessment.

### Basic Syntax

```bash
nmap [Scan Type(s)] [Options] {targets}
```

---

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

---

### Port Specification

```bash
nmap -p 22
nmap -p 1-1000
nmap -p 80,443,8080
nmap -p-
nmap -p http,https
nmap --top-ports 100
```

---

### Scan Types

```bash
nmap -sS      # TCP SYN scan (stealth)
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

---

### Timing & Performance

```bash
nmap -T0      # Paranoid (slowest)
nmap -T1      # Sneaky
nmap -T2      # Polite
nmap -T3      # Normal
nmap -T4      # Aggressive
nmap -T5      # Insane (fastest)
nmap --min-rate 100
nmap --max-rate 1000
nmap --host-timeout 30m
nmap --max-retries 2
nmap --min-parallelism 10
nmap --max-parallelism 100
```

---

### Output Options

```bash
nmap -oN results.txt         # Normal
nmap -oX results.xml         # XML
nmap -oG results.gnmap       # Grepable
nmap -oA basename            # All formats
nmap -v, -vv, -vvv           # Verbosity
nmap -d, -d2                 # Debugging
nmap --reason                # Show reasons for results
nmap --open                  # Show only open ports
nmap --stats-every 10s       # Periodic stats
```

---

### Service & Version Detection

```bash
nmap -sV                     # Version detection
nmap --version-intensity 5   # Intensity (0-9)
nmap --version-light         # Light version scan
nmap --version-all           # Try all probes
nmap --allports              # Scan all ports for version
```

---

### OS Detection

```bash
nmap -O                      # OS detection
nmap --osscan-limit          # Limit OS scan to promising targets
nmap --osscan-guess          # Guess OS more aggressively
```

---

### NSE Scripting Engine

```bash
nmap -sC                     # Default scripts
nmap --script http-title
nmap --script "vuln"
nmap --script "http-title and http-headers"
nmap --script-args 'user=admin,pass=admin'
nmap --script-trace
nmap --script-updatedb       # Update script DB
nmap --script-help=ssl-heartbleed
```

---

### Firewall/IDS Evasion

```bash
nmap -f                      # Fragment packets
nmap --mtu 16                # Set MTU
nmap -D RND:10               # Decoy scan
nmap -S 192.168.1.100        # Spoof source IP
nmap --source-port 53        # Set source port
nmap --data-length 25        # Append random data
nmap --randomize-hosts
nmap --proxies http://proxy:8080
nmap --spoof-mac 0           # Random MAC
nmap --badsum                # Send packets with invalid checksums
```

---

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

---

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

---

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

---

## References

- [Nmap Documentation](https://nmap.org/book/man.html)
- [Masscan GitHub](https://github.com/robertdavidgraham/masscan)
- `nmap --help` and `masscan --help` for more options

---

**Stay safe, scan responsibly!**
