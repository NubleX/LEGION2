// NDJSON + Rust is a sweet spot: small files, fast writes, easy to grep,
// and trivial to pipe into DuckDB later. Below is a minimal, production-leaning skeleton that:
// Sniffs only replies you care about (scanner-aware BPF)
// Extracts rich TCP/UDP/ICMP metadata (no payload by default)
// Writes compressed NDJSON with simple size-based rotation
// Adds MAC→OUI vendor enrichment hook
// Includes a clean SSDP probe you can reuse for “spidering” IoT
// Your Rust prober + sniffer finds living hosts/ports fast.
// Push interesting targets (small list) into Nmap for service/version/NSE.
// You get speed and rich semantics without re-implementing Rome.
// “Bots” you can build (fast wins)
// All of these are tiny modules + a BPF to capture replies:
// SYN prober (masscan-lite)
// TX: raw Ethernet/TCP SYNs; RX BPF:
// tcp and dst host $SCANNER_IP and dst portrange $EP_LO-$EP_HI and (tcp[13] & 0x12 != 0)
// Store: TTL, DF, IPID, TCP MSS/WS/SACK, window size, options hash.
// UDP ping (service-aware)
// TX: empty or service-specific payloads to common UDP ports (53/123/161/1900/5353/…);
// RX BPFs:
// icmp and dst host $SCANNER_IP and icmp[0]=3 (port unreachable → closed)
// udp and dst host $SCANNER_IP and dst portrange $EP_LO-$EP_HI (app replies → open)
// SSDP spider (your probe_ssdp)
// TX: M-SEARCH; RX: udp and src port 1900 and dst host $SCANNER_IP
// Parse LOCATION/USN/Server headers → device model, firmware hints.
// mDNS enumerator
// TX: _services._dns-sd._udp.local query; RX: udp and port 5353 multicast replies.
// Fingerprint printers, cams, TVs, HomeKit, etc.
// NetBIOS/LLMNR probes
// Quick wins on Windowsy LANs: udp and (port 137 or port 5355).
// ARP sweep (L2)
// TX: ARP who-has; RX: ARP is-at; ties neatly into your OUI enrichment.
// TLS/QUIC hello fingerprinter (lightweight “JA3/JA4” style)
// TX: ClientHello with canonical cipher list; RX: ServerHello → JA3S-like hash, SNI, ALPN.
// ICMP-based topology pinger
// TX: echo, timestamp, unreachable triggers; RX: ICMP types/codes, TTL/hop.
// Each bot is ~100–200 LOC with your logging harness.
// Snort/Suricata-ish “piggy” mode
// Passive sensor on a SPAN/TAP with a handful of header-only heuristics:
// TCP options hash + TTL/DF/ID “OS smell” → coarse OS buckets.
// Service discovery (SSDP/mDNS/DHCP, no payload storage by default).
// Anomaly counters: excessive RST, half-opens, TTL variance per host.
// You can add a tiny rule engine later (think: “if UDP/1900 reply and Server: X → tag as UPnP camera class”).
// BPF & performance tips
// Use a bigger buffer: Capture::from_device(dev)?.buffer_size(8<<20) before open().
// Stick to header-only matching in BPF; push deeper decisions to Rust.
// If you need >1 Gbps sustained, consider AF_PACKET with TPACKET_V3 or PF_RING; libpcap can still be fine with proper buffering.
// Keep hot loops allocation-free (your slice approach is good).
// Serialize NDJSON into a Vec<u8> and write once per event (as above).
// Clean fixes right now (surgical)
// Switch to SlicedPacket everywhere.
// Fix TCP options loop to exact enum names.
// Make flags a u8 (always) and compute it consistently.
// Count bytes for rotation (or rename to lines_written).
// Add a UDP+ICMP capture path alongside your TCP path.
// Remove unused imports; pin crate versions; run cargo clippy -W clippy::all.
// If you want, paste me your current Cargo.toml and the exact etherparse/pcap versions. I’ll snap your matches and the TCP options code to those APIs so the IDE calms down. //Then we can bolt on a UDP bot and a tiny ICMP catcher to round out your “replace-80%-of-Nmap-triage” playbook.

use anyhow::{anyhow, Result};
use chrono::Utc;
use etherparse::{PacketHeaders, TcpHeader, TcpOptionElement, TcpOptionsIterator};
use pcap::{Active, Capture, Device};
use serde::Serialize;
use serde_json::json;
use std::collections::VecDeque;
use std::fs::{create_dir_all, File, OpenOptions};
use std::io::Write;
use std::net::{Ipv4Addr, Ipv6Addr, UdpSocket};
use std::path::{Path, PathBuf};
use crate::commands::engine_commands;

// Minimal packet info for channel communication
struct PacketInfo {
    data: Vec<u8>,
    len: u32,
    ts_sec: i64,
    ts_usec: i64,
}

#[derive(Serialize)]
struct PktMeta {
    // timestamps
    ts_ns: u128,
    ts: String,

    // L2
    src_mac: String,
    dst_mac: String,
    oui_vendor: Option<String>,

    // L3/L4
    l3: &'static str,    // "ipv4" | "ipv6"
    proto: &'static str, // "tcp" | "udp" | "icmp" | "icmp6" | "other"
    src_ip: String,
    dst_ip: String,
    sport: Option<u16>,
    dport: Option<u16>,

    // IPv4 hints
    ttl_hop: u8,
    ip_df: Option<bool>,
    ip_id: Option<u16>,

    // TCP detail
    flags: Option<u8>,
    tcp_win: Option<u16>,
    tcp_mss: Option<u16>,
    tcp_wscale: Option<u8>,
    tcp_sack_ok: Option<bool>,
    tcp_opts_hash: Option<u64>,

    // packet size
    pkt_len: u32,

    // correlation
    dir: &'static str,                // "in"
    scan_id: Option<String>,          // fill if you track scans
    probe_type: Option<&'static str>, // "syn" | "ack" | "fin" | "udp" | ...
    vantage: String,
    iface: String,

    // optional sidecar
    evidence_path: Option<String>,
}

struct NdjsonZstdWriter {
    base_dir: PathBuf,
    max_bytes: u64,
    bytes_written: u64,
    file_idx: u64,
    enc: zstd::stream::write::Encoder<'static, File>,
}

impl NdjsonZstdWriter {
    fn new<P: AsRef<Path>>(dir: P, max_bytes: u64) -> Result<Self> {
        let dir = dir.as_ref();
        create_dir_all(dir)?;
        let (file_idx, enc) = Self::open_new(dir, 0)?;
        Ok(Self {
            base_dir: dir.to_path_buf(),
            max_bytes,
            bytes_written: 0,
            file_idx,
            enc,
        })
    }

    fn open_new(
        dir: &Path,
        idx: u64,
    ) -> Result<(u64, zstd::stream::write::Encoder<'static, File>)> {
        let ts = Utc::now().format("%Y%m%dT%H%M%S").to_string();
        let path = dir.join(format!("sniff_{ts}_{idx:06}.ndjson.zst"));
        let f = File::create(path)?;
        let enc = zstd::stream::write::Encoder::new(f, 7)?;
        Ok((idx, enc))
    }

    fn rotate(&mut self) -> Result<()> {
        self.file_idx += 1;
        let (idx, enc) = Self::open_new(&self.base_dir, self.file_idx)?;
        self.enc = enc;
        self.bytes_written = 0;
        self.file_idx = idx;
        Ok(())
    }

    fn write_json<T: Serialize>(&mut self, v: &T) -> Result<()> {
        serde_json::to_writer(&mut self.enc, v)?;
        self.enc.write_all(b"\n")?;
        self.bytes_written += 1; // count lines; size-only rotation below will still work
        Ok(())
    }

    fn maybe_rotate_by_size(&mut self) -> Result<()> {
        // We don't have direct bytes_written on the encoder. Cheap approximation:
        // rotate every N lines, or check file size occasionally if you keep a handle.
        // Here: rotate every 1,000,000 events; tweak as needed.
        if self.bytes_written >= self.max_bytes {
            self.rotate()?;
        }
        Ok(())
    }
}

fn format_mac(mac: [u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}

use std::collections::HashMap;
use std::u8;

fn oui_vendor_map() -> HashMap<[u8; 3], &'static str> {
    let mut map = HashMap::new();

    // Major vendors - first 3 bytes (OUI)
    map.insert([0x00, 0x1A, 0x11], "Google, Inc.");
    map.insert([0x00, 0x50, 0x56], "VMware, Inc.");
    map.insert([0x00, 0x0C, 0x29], "VMware, Inc.");
    map.insert([0x00, 0x05, 0x69], "VMware, Inc.");
    map.insert([0x00, 0x1C, 0x14], "VMware, Inc.");
    map.insert([0x00, 0x23, 0x20], "Apple, Inc.");
    map.insert([0x00, 0x1B, 0x63], "Apple, Inc.");
    map.insert([0x00, 0x1F, 0x5B], "Apple, Inc.");
    map.insert([0x00, 0x25, 0x00], "Apple, Inc.");
    map.insert([0x28, 0xCF, 0xDA], "Apple, Inc.");
    map.insert([0x40, 0x6C, 0x8F], "Apple, Inc.");
    map.insert([0x44, 0xD9, 0xE7], "Apple, Inc.");
    map.insert([0x4C, 0x32, 0x75], "Apple, Inc.");
    map.insert([0x00, 0x15, 0x5D], "Microsoft Corporation");
    map.insert([0x00, 0x12, 0x3F], "Microsoft Corporation");
    map.insert([0x00, 0x17, 0xFA], "Microsoft Corporation");
    map.insert([0x00, 0x03, 0xFF], "Microsoft Corporation");
    map.insert([0x00, 0x13, 0x20], "Dell Inc.");
    map.insert([0x00, 0x14, 0x22], "Dell Inc.");
    map.insert([0x00, 0x1A, 0xA0], "Dell Inc.");
    map.insert([0x00, 0x21, 0x9B], "Dell Inc.");
    map.insert([0x00, 0x24, 0xE8], "Dell Inc.");
    map.insert([0x00, 0x26, 0xB9], "Dell Inc.");
    map.insert([0x84, 0x2B, 0x2B], "Dell Inc.");
    map.insert([0xD0, 0x67, 0xE5], "Dell Inc.");
    map.insert([0x00, 0x0F, 0x1F], "Dell Inc.");
    map.insert([0x00, 0x19, 0xB9], "Dell Inc.");
    map.insert([0x00, 0x1E, 0xC9], "Dell Inc.");
    map.insert([0x00, 0x22, 0x19], "Dell Inc.");
    map.insert([0x00, 0x25, 0x64], "Dell Inc.");
    map.insert([0x00, 0x0A, 0x41], "Cisco Systems, Inc");
    map.insert([0x00, 0x0B, 0x45], "Cisco Systems, Inc");
    map.insert([0x00, 0x0C, 0x85], "Cisco Systems, Inc");
    map.insert([0x00, 0x0D, 0xBD], "Cisco Systems, Inc");
    map.insert([0x00, 0x0E, 0x83], "Cisco Systems, Inc");
    map.insert([0x00, 0x0F, 0x23], "Cisco Systems, Inc");
    map.insert([0x00, 0x0F, 0x34], "Cisco Systems, Inc");
    map.insert([0x00, 0x11, 0x21], "Cisco Systems, Inc");
    map.insert([0x00, 0x11, 0x5C], "Cisco Systems, Inc");
    map.insert([0x00, 0x11, 0x93], "Cisco Systems, Inc");
    map.insert([0x00, 0x12, 0x00], "Cisco Systems, Inc");
    map.insert([0x00, 0x12, 0x43], "Cisco Systems, Inc");
    map.insert([0x00, 0x12, 0x7F], "Cisco Systems, Inc");
    map.insert([0x00, 0x12, 0xDA], "Cisco Systems, Inc");
    map.insert([0x00, 0x13, 0x19], "Cisco Systems, Inc");
    map.insert([0x00, 0x13, 0x7F], "Cisco Systems, Inc");
    map.insert([0x00, 0x13, 0xC4], "Cisco Systems, Inc");
    map.insert([0x00, 0x14, 0x1C], "Cisco Systems, Inc");
    map.insert([0x00, 0x14, 0x69], "Cisco Systems, Inc");
    map.insert([0x00, 0x14, 0xA9], "Cisco Systems, Inc");
    map.insert([0x00, 0x14, 0xF1], "Cisco Systems, Inc");
    map.insert([0x00, 0x15, 0x62], "Cisco Systems, Inc");
    map.insert([0x00, 0x15, 0x63], "Cisco Systems, Inc");
    map.insert([0x00, 0x15, 0xC6], "Cisco Systems, Inc");
    map.insert([0x00, 0x15, 0xF9], "Cisco Systems, Inc");
    map.insert([0x00, 0x16, 0x46], "Cisco Systems, Inc");
    map.insert([0x00, 0x16, 0x47], "Cisco Systems, Inc");
    map.insert([0x00, 0x16, 0x9C], "Cisco Systems, Inc");
    map.insert([0x00, 0x16, 0xC7], "Cisco Systems, Inc");
    map.insert([0x00, 0x17, 0x0E], "Cisco Systems, Inc");
    map.insert([0x00, 0x17, 0x5A], "Cisco Systems, Inc");
    map.insert([0x00, 0x17, 0x94], "Cisco Systems, Inc");
    map.insert([0x00, 0x17, 0xDF], "Cisco Systems, Inc");
    map.insert([0x00, 0x18, 0x18], "Cisco Systems, Inc");
    map.insert([0x00, 0x18, 0x19], "Cisco Systems, Inc");
    map.insert([0x00, 0x18, 0x68], "Cisco Systems, Inc");
    map.insert([0x00, 0x18, 0x73], "Cisco Systems, Inc");
    map.insert([0x00, 0x18, 0xB9], "Cisco Systems, Inc");
    map.insert([0x00, 0x18, 0xBA], "Cisco Systems, Inc");
    map.insert([0x00, 0x19, 0x06], "Cisco Systems, Inc");
    map.insert([0x00, 0x19, 0x07], "Cisco Systems, Inc");
    map.insert([0x00, 0x19, 0x2F], "Cisco Systems, Inc");
    map.insert([0x00, 0x19, 0x30], "Cisco Systems, Inc");
    map.insert([0x00, 0x19, 0x47], "Cisco Systems, Inc");
    map.insert([0x00, 0x19, 0x55], "Cisco Systems, Inc");
    map.insert([0x00, 0x19, 0x56], "Cisco Systems, Inc");
    map.insert([0x00, 0x19, 0xE7], "Cisco Systems, Inc");
    map.insert([0x00, 0x1A, 0x2F], "Cisco Systems, Inc");
    map.insert([0x00, 0x1A, 0x30], "Cisco Systems, Inc");
    map.insert([0x00, 0x1A, 0x6C], "Cisco Systems, Inc");
    map.insert([0x00, 0x1A, 0x6D], "Cisco Systems, Inc");
    map.insert([0x00, 0x1A, 0xA1], "Cisco Systems, Inc");
    map.insert([0x00, 0x1A, 0xA2], "Cisco Systems, Inc");
    map.insert([0x00, 0x1B, 0x0C], "Cisco Systems, Inc");
    map.insert([0x00, 0x1B, 0x0D], "Cisco Systems, Inc");
    map.insert([0x00, 0x1B, 0x2A], "Cisco Systems, Inc");
    map.insert([0x00, 0x1B, 0x2B], "Cisco Systems, Inc");
    map.insert([0x00, 0x1B, 0x53], "Cisco Systems, Inc");
    map.insert([0x00, 0x1B, 0x54], "Cisco Systems, Inc");
    map.insert([0x00, 0x1B, 0x67], "Cisco Systems, Inc");
    map.insert([0x00, 0x1B, 0x68], "Cisco Systems, Inc");
    map.insert([0x00, 0x1B, 0xD4], "Cisco Systems, Inc");
    map.insert([0x00, 0x1B, 0xD5], "Cisco Systems, Inc");
    map.insert([0x00, 0x1C, 0x0E], "Cisco Systems, Inc");
    map.insert([0x00, 0x1C, 0x0F], "Cisco Systems, Inc");
    map.insert([0x00, 0x1C, 0x57], "Cisco Systems, Inc");
    map.insert([0x00, 0x1C, 0x58], "Cisco Systems, Inc");
    map.insert([0x00, 0x1C, 0xB0], "Cisco Systems, Inc");
    map.insert([0x00, 0x1C, 0xB1], "Cisco Systems, Inc");
    map.insert([0x00, 0x1D, 0x45], "Cisco Systems, Inc");
    map.insert([0x00, 0x1D, 0x46], "Cisco Systems, Inc");
    map.insert([0x00, 0x1D, 0x70], "Cisco Systems, Inc");
    map.insert([0x00, 0x1D, 0x71], "Cisco Systems, Inc");
    map.insert([0x00, 0x1D, 0xA1], "Cisco Systems, Inc");
    map.insert([0x00, 0x1D, 0xA2], "Cisco Systems, Inc");
    map.insert([0x00, 0x1E, 0x13], "Cisco Systems, Inc");
    map.insert([0x00, 0x1E, 0x14], "Cisco Systems, Inc");
    map.insert([0x00, 0x1E, 0x49], "Cisco Systems, Inc");
    map.insert([0x00, 0x1E, 0x4A], "Cisco Systems, Inc");
    map.insert([0x00, 0x1E, 0x7A], "Cisco Systems, Inc");
    map.insert([0x00, 0x1E, 0x7B], "Cisco Systems, Inc");
    map.insert([0x00, 0x1E, 0xBD], "Cisco Systems, Inc");
    map.insert([0x00, 0x1E, 0xBE], "Cisco Systems, Inc");
    map.insert([0x00, 0x1E, 0xF6], "Cisco Systems, Inc");
    map.insert([0x00, 0x1E, 0xF7], "Cisco Systems, Inc");
    map.insert([0x00, 0x1F, 0x26], "Cisco Systems, Inc");
    map.insert([0x00, 0x1F, 0x27], "Cisco Systems, Inc");
    map.insert([0x00, 0x1F, 0x6C], "Cisco Systems, Inc");
    map.insert([0x00, 0x1F, 0x6D], "Cisco Systems, Inc");
    map.insert([0x00, 0x1F, 0x9E], "Cisco Systems, Inc");
    map.insert([0x00, 0x1F, 0x9F], "Cisco Systems, Inc");
    map.insert([0x00, 0x1F, 0xCA], "Cisco Systems, Inc");
    map.insert([0x00, 0x1F, 0xCB], "Cisco Systems, Inc");
    map.insert([0x00, 0x20, 0x35], "Cisco Systems, Inc");
    map.insert([0x00, 0x20, 0x36], "Cisco Systems, Inc");
    map.insert([0x00, 0x20, 0xBA], "Cisco Systems, Inc");
    map.insert([0x00, 0x20, 0xBB], "Cisco Systems, Inc");
    map.insert([0x00, 0x21, 0x1B], "Cisco Systems, Inc");
    map.insert([0x00, 0x21, 0x1C], "Cisco Systems, Inc");
    map.insert([0x00, 0x21, 0x55], "Cisco Systems, Inc");
    map.insert([0x00, 0x21, 0x56], "Cisco Systems, Inc");
    map.insert([0x00, 0x21, 0xA0], "Cisco Systems, Inc");
    map.insert([0x00, 0x21, 0xA1], "Cisco Systems, Inc");
    map.insert([0x00, 0x21, 0xD7], "Cisco Systems, Inc");
    map.insert([0x00, 0x21, 0xD8], "Cisco Systems, Inc");
    map.insert([0x00, 0x22, 0x0C], "Cisco Systems, Inc");
    map.insert([0x00, 0x22, 0x0D], "Cisco Systems, Inc");
    map.insert([0x00, 0x22, 0x55], "Cisco Systems, Inc");
    map.insert([0x00, 0x22, 0x56], "Cisco Systems, Inc");
    map.insert([0x00, 0x22, 0x90], "Cisco Systems, Inc");
    map.insert([0x00, 0x22, 0x91], "Cisco Systems, Inc");
    map.insert([0x00, 0x22, 0xBD], "Cisco Systems, Inc");
    map.insert([0x00, 0x22, 0xBE], "Cisco Systems, Inc");
    map.insert([0x00, 0x22, 0xCE], "Cisco Systems, Inc");
    map.insert([0x00, 0x22, 0xCF], "Cisco Systems, Inc");
    map.insert([0x00, 0x23, 0x04], "Cisco Systems, Inc");
    map.insert([0x00, 0x23, 0x05], "Cisco Systems, Inc");
    map.insert([0x00, 0x23, 0x33], "Cisco Systems, Inc");
    map.insert([0x00, 0x23, 0x34], "Cisco Systems, Inc");
    map.insert([0x00, 0x23, 0x5D], "Cisco Systems, Inc");
    map.insert([0x00, 0x23, 0x5E], "Cisco Systems, Inc");
    map.insert([0x00, 0x23, 0xAB], "Cisco Systems, Inc");
    map.insert([0x00, 0x23, 0xAC], "Cisco Systems, Inc");
    map.insert([0x00, 0x23, 0xBE], "Cisco Systems, Inc");
    map.insert([0x00, 0x23, 0xBF], "Cisco Systems, Inc");
    map.insert([0x00, 0x23, 0xEA], "Cisco Systems, Inc");
    map.insert([0x00, 0x23, 0xEB], "Cisco Systems, Inc");
    map.insert([0x00, 0x24, 0x13], "Cisco Systems, Inc");
    map.insert([0x00, 0x24, 0x14], "Cisco Systems, Inc");
    map.insert([0x00, 0x24, 0x50], "Cisco Systems, Inc");
    map.insert([0x00, 0x24, 0x51], "Cisco Systems, Inc");
    map.insert([0x00, 0x24, 0x97], "Cisco Systems, Inc");
    map.insert([0x00, 0x24, 0x98], "Cisco Systems, Inc");
    map.insert([0x00, 0x24, 0xC3], "Cisco Systems, Inc");
    map.insert([0x00, 0x24, 0xC4], "Cisco Systems, Inc");
    map.insert([0x00, 0x24, 0xF7], "Cisco Systems, Inc");
    map.insert([0x00, 0x24, 0xF9], "Cisco Systems, Inc");
    map.insert([0x00, 0x25, 0x2E], "Cisco Systems, Inc");
    map.insert([0x00, 0x25, 0x45], "Cisco Systems, Inc");
    map.insert([0x00, 0x25, 0x46], "Cisco Systems, Inc");
    map.insert([0x00, 0x25, 0x83], "Cisco Systems, Inc");
    map.insert([0x00, 0x25, 0x84], "Cisco Systems, Inc");
    map.insert([0x00, 0x25, 0xB4], "Cisco Systems, Inc");
    map.insert([0x00, 0x25, 0xB5], "Cisco Systems, Inc");
    map.insert([0x00, 0x26, 0x0A], "Cisco Systems, Inc");
    map.insert([0x00, 0x26, 0x0B], "Cisco Systems, Inc");
    map.insert([0x00, 0x26, 0x51], "Cisco Systems, Inc");
    map.insert([0x00, 0x26, 0x52], "Cisco Systems, Inc");
    map.insert([0x00, 0x26, 0x98], "Cisco Systems, Inc");
    map.insert([0x00, 0x26, 0x99], "Cisco Systems, Inc");
    map.insert([0x00, 0x26, 0xCA], "Cisco Systems, Inc");
    map.insert([0x00, 0x26, 0xCB], "Cisco Systems, Inc");
    map.insert([0x00, 0x27, 0x0C], "Cisco Systems, Inc");
    map.insert([0x00, 0x27, 0x0D], "Cisco Systems, Inc");
    map.insert([0x00, 0x27, 0x90], "Cisco Systems, Inc");
    map.insert([0x00, 0x27, 0x91], "Cisco Systems, Inc");
    map.insert([0x00, 0x40, 0x96], "Cisco Systems, Inc");

    // Intel Corporation
    map.insert([0x00, 0x02, 0xB3], "Intel Corporation");
    map.insert([0x00, 0x03, 0x47], "Intel Corporation");
    map.insert([0x00, 0x07, 0xE9], "Intel Corporation");
    map.insert([0x00, 0x0E, 0x0C], "Intel Corporation");
    map.insert([0x00, 0x13, 0x02], "Intel Corporation");
    map.insert([0x00, 0x13, 0x20], "Intel Corporation");
    map.insert([0x00, 0x15, 0x17], "Intel Corporation");
    map.insert([0x00, 0x16, 0x76], "Intel Corporation");
    map.insert([0x00, 0x19, 0xD1], "Intel Corporation");
    map.insert([0x00, 0x1B, 0x21], "Intel Corporation");
    map.insert([0x00, 0x1E, 0x64], "Intel Corporation");
    map.insert([0x00, 0x1E, 0x65], "Intel Corporation");
    map.insert([0x00, 0x1F, 0x3A], "Intel Corporation");
    map.insert([0x00, 0x1F, 0x3B], "Intel Corporation");
    map.insert([0x00, 0x1F, 0x3C], "Intel Corporation");
    map.insert([0x00, 0x21, 0x6A], "Intel Corporation");
    map.insert([0x00, 0x21, 0x6B], "Intel Corporation");
    map.insert([0x00, 0x22, 0xFA], "Intel Corporation");
    map.insert([0x00, 0x22, 0xFB], "Intel Corporation");
    map.insert([0x00, 0x24, 0xD6], "Intel Corporation");
    map.insert([0x00, 0x24, 0xD7], "Intel Corporation");
    map.insert([0x00, 0x26, 0x5A], "Intel Corporation");
    map.insert([0x00, 0x26, 0x5B], "Intel Corporation");
    map.insert([0x00, 0x27, 0x10], "Intel Corporation");
    map.insert([0x00, 0x27, 0x11], "Intel Corporation");
    map.insert([0x3C, 0x97, 0x0E], "Intel Corporation");
    map.insert([0x40, 0xA8, 0xF0], "Intel Corporation");
    map.insert([0x44, 0x85, 0x00], "Intel Corporation");
    map.insert([0x4C, 0x79, 0xBA], "Intel Corporation");
    map.insert([0x68, 0x05, 0xCA], "Intel Corporation");
    map.insert([0x6C, 0x62, 0x6D], "Intel Corporation");
    map.insert([0x78, 0x0C, 0xB8], "Intel Corporation");
    map.insert([0x7C, 0x7A, 0x91], "Intel Corporation");
    map.insert([0x84, 0x39, 0xBE], "Intel Corporation");
    map.insert([0x88, 0x51, 0xFB], "Intel Corporation");
    map.insert([0x94, 0xC6, 0x91], "Intel Corporation");
    map.insert([0x9C, 0xB6, 0xD0], "Intel Corporation");
    map.insert([0xA0, 0xA8, 0xCD], "Intel Corporation");
    map.insert([0xA4, 0x02, 0xB9], "Intel Corporation");
    map.insert([0xA4, 0x4C, 0xC8], "Intel Corporation");
    map.insert([0xB4, 0x96, 0x91], "Intel Corporation");
    map.insert([0xB8, 0xAE, 0xED], "Intel Corporation");
    map.insert([0xCC, 0x46, 0xD6], "Intel Corporation");
    map.insert([0xD0, 0x57, 0x7B], "Intel Corporation");
    map.insert([0xD4, 0xBE, 0xD9], "Intel Corporation");
    map.insert([0xE0, 0x94, 0x67], "Intel Corporation");
    map.insert([0xE4, 0xA7, 0xA0], "Intel Corporation");
    map.insert([0xF0, 0x76, 0x1C], "Intel Corporation");
    map.insert([0xF4, 0x4D, 0x30], "Intel Corporation");
    map.insert([0xFC, 0x77, 0x74], "Intel Corporation");

    // Additional common vendors
    map.insert([0x00, 0x04, 0x20], "Hewlett Packard");
    map.insert([0x00, 0x08, 0x02], "Hewlett Packard");
    map.insert([0x00, 0x10, 0x83], "Hewlett Packard");
    map.insert([0x00, 0x11, 0x85], "Hewlett Packard");
    map.insert([0x00, 0x12, 0x79], "Hewlett Packard");
    map.insert([0x00, 0x13, 0x21], "Hewlett Packard");
    map.insert([0x00, 0x14, 0xC2], "Hewlett Packard");
    map.insert([0x00, 0x15, 0x60], "Hewlett Packard");
    map.insert([0x00, 0x16, 0x35], "Hewlett Packard");
    map.insert([0x00, 0x17, 0x08], "Hewlett Packard");
    map.insert([0x00, 0x17, 0xA4], "Hewlett Packard");
    map.insert([0x00, 0x18, 0x71], "Hewlett Packard");
    map.insert([0x00, 0x18, 0xFE], "Hewlett Packard");
    map.insert([0x00, 0x19, 0xBB], "Hewlett Packard");
    map.insert([0x00, 0x1A, 0x4B], "Hewlett Packard");
    map.insert([0x00, 0x1B, 0x78], "Hewlett Packard");
    map.insert([0x00, 0x1C, 0xC4], "Hewlett Packard");
    map.insert([0x00, 0x1E, 0x0B], "Hewlett Packard");
    map.insert([0x00, 0x1F, 0x29], "Hewlett Packard");
    map.insert([0x00, 0x21, 0x5A], "Hewlett Packard");
    map.insert([0x00, 0x23, 0x47], "Hewlett Packard");
    map.insert([0x00, 0x24, 0x81], "Hewlett Packard");
    map.insert([0x00, 0x25, 0x61], "Hewlett Packard");
    map.insert([0x00, 0x26, 0x55], "Hewlett Packard");
    map.insert([0x04, 0x4B, 0xED], "Hewlett Packard");
    map.insert([0x08, 0x00, 0x09], "Hewlett Packard");
    map.insert([0x08, 0x2E, 0x5F], "Hewlett Packard");
    map.insert([0x0C, 0xC4, 0x7A], "Hewlett Packard");
    map.insert([0x10, 0x1F, 0x74], "Hewlett Packard");
    map.insert([0x14, 0x02, 0xEC], "Hewlett Packard");
    map.insert([0x14, 0x58, 0xD0], "Hewlett Packard");
    map.insert([0x18, 0xA9, 0x05], "Hewlett Packard");
    map.insert([0x1C, 0xC1, 0xDE], "Hewlett Packard");
    map.insert([0x2C, 0x27, 0xD7], "Hewlett Packard");
    map.insert([0x2C, 0x44, 0xFD], "Hewlett Packard");
    map.insert([0x2C, 0x59, 0xE5], "Hewlett Packard");
    map.insert([0x30, 0x8D, 0x99], "Hewlett Packard");
    map.insert([0x30, 0xE1, 0x71], "Hewlett Packard");
    map.insert([0x34, 0x64, 0xA9], "Hewlett Packard");
    map.insert([0x34, 0xFC, 0xEF], "Hewlett Packard");
    map.insert([0x38, 0xEA, 0xA7], "Hewlett Packard");
    map.insert([0x3C, 0x4A, 0x92], "Hewlett Packard");
    map.insert([0x3C, 0xA8, 0x2A], "Hewlett Packard");
    map.insert([0x3C, 0xD9, 0x2B], "Hewlett Packard");
    map.insert([0x40, 0xA8, 0xF0], "Hewlett Packard");
    map.insert([0x48, 0x0F, 0xCF], "Hewlett Packard");
    map.insert([0x4C, 0x39, 0x09], "Hewlett Packard");
    map.insert([0x50, 0x65, 0xF3], "Hewlett Packard");
    map.insert([0x5C, 0xB9, 0x01], "Hewlett Packard");
    map.insert([0x5C, 0xE0, 0xC5], "Hewlett Packard");
    map.insert([0x64, 0x31, 0x50], "Hewlett Packard");
    map.insert([0x68, 0xB5, 0x99], "Hewlett Packard");
    map.insert([0x6C, 0x3B, 0xE5], "Hewlett Packard");
    map.insert([0x70, 0x10, 0x6F], "Hewlett Packard");
    map.insert([0x78, 0xAC, 0xC0], "Hewlett Packard");
    map.insert([0x80, 0xC1, 0x6E], "Hewlett Packard");
    map.insert([0x84, 0x34, 0x97], "Hewlett Packard");
    map.insert([0x9C, 0x8E, 0x99], "Hewlett Packard");
    map.insert([0xA0, 0xB3, 0xCC], "Hewlett Packard");
    map.insert([0xA4, 0x5D, 0x36], "Hewlett Packard");
    map.insert([0xB0, 0x83, 0xFE], "Hewlett Packard");
    map.insert([0xB4, 0x39, 0xD6], "Hewlett Packard");
    map.insert([0xB4, 0x99, 0xBA], "Hewlett Packard");
    map.insert([0xC8, 0xCB, 0xB8], "Hewlett Packard");
    map.insert([0xCC, 0x3E, 0x5F], "Hewlett Packard");
    map.insert([0xD0, 0xBF, 0x9C], "Hewlett Packard");
    map.insert([0xD4, 0x85, 0x64], "Hewlett Packard");
    map.insert([0xD4, 0xC9, 0xEF], "Hewlett Packard");
    map.insert([0xDC, 0x4A, 0x3E], "Hewlett Packard");
    map.insert([0xE8, 0x39, 0x35], "Hewlett Packard");
    map.insert([0xEC, 0xB1, 0xD7], "Hewlett Packard");
    map.insert([0xF0, 0x92, 0x1C], "Hewlett Packard");
    map.insert([0xF4, 0xCE, 0x46], "Hewlett Packard");
    map.insert([0xFC, 0x15, 0xB4], "Hewlett Packard");

    // Additional common networking vendors
    map.insert([0x00, 0x0B, 0x86], "Arris Group, Inc.");
    map.insert([0x00, 0x15, 0xA3], "Arris Group, Inc.");
    map.insert([0x00, 0x18, 0x36], "Arris Group, Inc.");
    map.insert([0x00, 0x1A, 0xC1], "Arris Group, Inc.");
    map.insert([0x00, 0x1E, 0x46], "Arris Group, Inc.");
    map.insert([0x00, 0x21, 0x86], "Arris Group, Inc.");
    map.insert([0x00, 0x23, 0x69], "Arris Group, Inc.");
    map.insert([0x00, 0x24, 0xA0], "Arris Group, Inc.");
    map.insert([0x00, 0x26, 0x24], "Arris Group, Inc.");

    map.insert([0x00, 0x04, 0x5A], "Linksys");
    map.insert([0x00, 0x06, 0x25], "Linksys");
    map.insert([0x00, 0x0C, 0x41], "Linksys");
    map.insert([0x00, 0x0F, 0x66], "Linksys");
    map.insert([0x00, 0x12, 0x17], "Linksys");
    map.insert([0x00, 0x13, 0x10], "Linksys");
    map.insert([0x00, 0x14, 0xBF], "Linksys");
    map.insert([0x00, 0x16, 0xB6], "Linksys");
    map.insert([0x00, 0x18, 0x39], "Linksys");
    map.insert([0x00, 0x18, 0xF8], "Linksys");
    map.insert([0x00, 0x1A, 0x70], "Linksys");
    map.insert([0x00, 0x1C, 0x10], "Linksys");
    map.insert([0x00, 0x1D, 0x7E], "Linksys");
    map.insert([0x00, 0x1E, 0xE5], "Linksys");
    map.insert([0x00, 0x20, 0xA6], "Linksys");
    map.insert([0x00, 0x21, 0x29], "Linksys");
    map.insert([0x00, 0x22, 0x6B], "Linksys");
    map.insert([0x00, 0x23, 0x69], "Linksys");
    map.insert([0x00, 0x25, 0x9C], "Linksys");

    // Additional common mobile and IoT device vendors
    map.insert([0x18, 0x3D, 0xA2], "Samsung Electronics Co.,Ltd");
    map.insert([0x18, 0x47, 0x3D], "Samsung Electronics Co.,Ltd");
    map.insert([0x18, 0x59, 0x36], "Samsung Electronics Co.,Ltd");
    map.insert([0x18, 0x66, 0xDA], "Samsung Electronics Co.,Ltd");
    map.insert([0x1C, 0x62, 0xB8], "Samsung Electronics Co.,Ltd");
    map.insert([0x1C, 0x66, 0xAA], "Samsung Electronics Co.,Ltd");
    map.insert([0x1C, 0x69, 0x7A], "Samsung Electronics Co.,Ltd");
    map.insert([0x1C, 0x6A, 0x7A], "Samsung Electronics Co.,Ltd");
    map.insert([0x20, 0x02, 0xAF], "Samsung Electronics Co.,Ltd");
    map.insert([0x20, 0x13, 0xE0], "Samsung Electronics Co.,Ltd");
    map.insert([0x20, 0x15, 0x20], "Samsung Electronics Co.,Ltd");
    map.insert([0x20, 0x64, 0x32], "Samsung Electronics Co.,Ltd");
    map.insert([0x20, 0x6B, 0xE7], "Samsung Electronics Co.,Ltd");
    map.insert([0x20, 0x6E, 0x9C], "Samsung Electronics Co.,Ltd");
    map.insert([0x20, 0x79, 0x18], "Samsung Electronics Co.,Ltd");
    map.insert([0x24, 0x07, 0x77], "Samsung Electronics Co.,Ltd");
    map.insert([0x24, 0x0A, 0x64], "Samsung Electronics Co.,Ltd");
    map.insert([0x24, 0x4B, 0x03], "Samsung Electronics Co.,Ltd");
    map.insert([0x24, 0x4C, 0xE3], "Samsung Electronics Co.,Ltd");
    map.insert([0x24, 0x5A, 0x3C], "Samsung Electronics Co.,Ltd");
    map.insert([0x24, 0x62, 0xAB], "Samsung Electronics Co.,Ltd");
    map.insert([0x24, 0x69, 0x68], "Samsung Electronics Co.,Ltd");
    map.insert([0x28, 0xBA, 0xB5], "Samsung Electronics Co.,Ltd");
    map.insert([0x28, 0xCC, 0x01], "Samsung Electronics Co.,Ltd");
    map.insert([0x28, 0xCD, 0xC1], "Samsung Electronics Co.,Ltd");
    map.insert([0x28, 0xE3, 0x47], "Samsung Electronics Co.,Ltd");
    map.insert([0x28, 0xE7, 0xCF], "Samsung Electronics Co.,Ltd");

    map.insert([0x00, 0x08, 0x74], "Netgear");
    map.insert([0x00, 0x09, 0x5B], "Netgear");
    map.insert([0x00, 0x0F, 0xB5], "Netgear");
    map.insert([0x00, 0x14, 0x6C], "Netgear");
    map.insert([0x00, 0x18, 0x4D], "Netgear");
    map.insert([0x00, 0x1B, 0x2F], "Netgear");
    map.insert([0x00, 0x1E, 0x2A], "Netgear");
    map.insert([0x00, 0x22, 0x3F], "Netgear");
    map.insert([0x00, 0x24, 0xB2], "Netgear");
    map.insert([0x00, 0x26, 0xF2], "Netgear");
    map.insert([0x04, 0xBF, 0x6D], "Netgear");
    map.insert([0x08, 0xBD, 0x43], "Netgear");
    map.insert([0x0C, 0x80, 0x63], "Netgear");
    map.insert([0x10, 0x0D, 0x7F], "Netgear");
    map.insert([0x20, 0x4E, 0x7F], "Netgear");
    map.insert([0x28, 0xC6, 0x8E], "Netgear");
    map.insert([0x2C, 0x30, 0x33], "Netgear");
    map.insert([0x30, 0x46, 0x9A], "Netgear");
    map.insert([0x44, 0x94, 0xFC], "Netgear");
    map.insert([0x6C, 0x19, 0x8F], "Netgear");
    map.insert([0x84, 0x1B, 0x5E], "Netgear");
    map.insert([0x90, 0xA7, 0xC1], "Netgear");
    map.insert([0x9C, 0x3D, 0xCF], "Netgear");
    map.insert([0xA0, 0x04, 0x60], "Netgear");
    map.insert([0xA4, 0x2B, 0x8C], "Netgear");
    map.insert([0xC0, 0x3F, 0x0E], "Netgear");
    map.insert([0xC4, 0x04, 0x15], "Netgear");
    map.insert([0xE0, 0x46, 0x9A], "Netgear");

    map
}

pub fn oui_lookup_vendor(mac: [u8; 6]) -> Option<String> {
    let oui_map = oui_vendor_map();
    let oui = [mac[0], mac[1], mac[2]];
    oui_map.get(&oui).map(|vendor| vendor.to_string())
}

fn hash_opts_kinds(kinds: &[u8]) -> u64 {
    // FNV-1a
    const OFF: u64 = 0xcbf29ce484222325;
    const PRM: u64 = 0x00000100000001B3;
    let mut h = OFF;
    for b in kinds {
        h ^= *b as u64;
        h = h.wrapping_mul(PRM);
    }
    h
}

fn main() -> Result<()> {
    // Config (quick & dirty). You can wire clap later.
    let scanner_ip = std::env::var("SCANNER_IP").unwrap_or_else(|_| "192.0.2.10".into());
    let ep_low: u16 = std::env::var("EP_LOW")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(40000);
    let ep_high: u16 = std::env::var("EP_HIGH")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(65000);
    let iface_name = std::env::var("IFACE").unwrap_or_else(|_| "default".into());
    let vantage = std::env::var("VANTAGE").unwrap_or_else(|_| "gw1".into());

    // Open capture
    let dev = if iface_name == "default" {
        Device::lookup()?.ok_or_else(|| anyhow!("no default capture device"))
    } else {
        Device::list()?
            .into_iter()
            .find(|d| d.name == iface_name)
            .ok_or_else(|| anyhow!("interface {} not found", iface_name))
    }?;

    let mut cap: Capture<Active> = Capture::from_device(dev)?
        .promisc(true)
        .immediate_mode(true)
        .timeout(10)
        .open()?;

    // BPF: only replies to our scanner ephemeral ports (SYN/ACK, FIN, RST, ACK)
    let bpf = format!(
        "tcp and dst host {scanner_ip} and dst portrange {ep_low}-{ep_high} and (tcp[13] & (0x01|0x04|0x10|0x12) != 0)"
    );
    cap.filter(&bpf, true)?;

    // Also consider: UDP replies & ICMP errors for UDP “drive-by” mapping (add another cap or switch filter when needed).

    let mut writer = NdjsonZstdWriter::new("data/ndjson", 1_000_000)?; // rotate every ~1M events

    loop {
        match cap.next_packet() {
            Ok(pkt) => {
                if let Some(meta) = handle_packet(&pkt.data, &pkt.header, &vantage, &iface_name) {
                    writer.write_json(&meta)?;
                    writer.maybe_rotate_by_size()?;
                }
            }
            Err(pcap::Error::TimeoutExpired) => continue,
            Err(e) => eprintln!("pcap error: {e}"),
        }
    }
}

fn handle_packet(
    raw: &[u8],
    h: &pcap::PacketHeader,
    vantage: &str,
    iface: &str,
) -> Option<PktMeta> {
    handle_packet_with_ts(raw, h.ts.tv_sec, h.ts.tv_usec, h.len, vantage, iface)
}

fn handle_packet_with_ts(
    raw: &[u8],
    ts_sec: i64,
    ts_usec: i64,
    pkt_len: u32,
    vantage: &str,
    iface: &str,
) -> Option<PktMeta> {
    let ph = PacketHeaders::from_ethernet_slice(raw).ok()?;
    // Ethernet
    let (src_mac, dst_mac) = match ph.link {
        Some(etherparse::LinkHeader::Ethernet2(e)) => (e.source, e.destination),
        _ => return None,
    };

    // IP & transport
    let (
        l3,
        src_ip,
        dst_ip,
        ttl_hop,
        ip_df,
        ip_id,
        proto,
        sport,
        dport,
        flags,
        tcp_win,
        mss,
        wscale,
        sack_ok,
        opt_kinds,
    ) = match (ph.net.as_ref(), ph.transport.as_ref()) {
        (
            Some(etherparse::NetHeaders::Ipv4(v4, _)),
            Some(etherparse::TransportHeader::Tcp(tcp)),
        ) => {
            let mut mss = None;
            let mut wscale = None;
            let mut sack_ok = None;
            let mut kinds: Vec<u8> = Vec::new();

            // Parse TCP options correctly
            let options_iter = etherparse::TcpOptionsIterator::from_slice(tcp.options.as_slice());
            for opt_result in options_iter {
                if let Ok(opt) = opt_result {
                    use etherparse::TcpOptionElement::*;
                    match opt {
                        MaximumSegmentSize(s) => {
                            mss = Some(s);
                            kinds.push(2);
                        }
                        WindowScale(ws) => {
                            wscale = Some(ws);
                            kinds.push(3);
                        }
                        SelectiveAckPermitted => {
                            sack_ok = Some(true);
                            kinds.push(4);
                        }
                        Timestamp(_, _) => kinds.push(8),
                        Noop => kinds.push(1),
                    }
                }
            }

            // Encode TCP flags into a single byte
            let mut tcp_flags: u8 = 0;
            if tcp.fin { tcp_flags |= 0x01; }
            if tcp.syn { tcp_flags |= 0x02; }
            if tcp.rst { tcp_flags |= 0x04; }
            if tcp.psh { tcp_flags |= 0x08; }
            if tcp.ack { tcp_flags |= 0x10; }
            if tcp.urg { tcp_flags |= 0x20; }
            if tcp.ece { tcp_flags |= 0x40; }
            if tcp.cwr { tcp_flags |= 0x80; }

            (
                "ipv4",
                Ipv4Addr::from(v4.source).to_string(),
                Ipv4Addr::from(v4.destination).to_string(),
                v4.time_to_live,
                Some(v4.dont_fragment),
                Some(v4.identification),
                "tcp",
                Some(tcp.source_port),
                Some(tcp.destination_port),
                Some(tcp_flags),
                Some(tcp.window_size),
                mss,
                wscale,
                sack_ok,
                kinds,
            )
        }
        (
            Some(etherparse::NetHeaders::Ipv6(v6, _)),
            Some(etherparse::TransportHeader::Tcp(tcp)),
        ) => {
            let mut mss = None;
            let mut wscale = None;
            let mut sack_ok = None;
            let mut kinds: Vec<u8> = Vec::new();

            // Parse TCP options correctly
            let options_iter = etherparse::TcpOptionsIterator::from_slice(tcp.options.as_slice());
            for opt_result in options_iter {
                if let Ok(opt) = opt_result {
                    use etherparse::TcpOptionElement::*;
                    match opt {
                        MaximumSegmentSize(s) => {
                            mss = Some(s);
                            kinds.push(2);
                        }
                        WindowScale(ws) => {
                            wscale = Some(ws);
                            kinds.push(3);
                        }
                        SelectiveAckPermitted => {
                            sack_ok = Some(true);
                            kinds.push(4);
                        }
                        Timestamp(_, _) => kinds.push(8),
                        Noop => kinds.push(1),
                    }
                }
            }

            // Encode TCP flags into a single byte
            let mut tcp_flags: u8 = 0;
            if tcp.fin { tcp_flags |= 0x01; }
            if tcp.syn { tcp_flags |= 0x02; }
            if tcp.rst { tcp_flags |= 0x04; }
            if tcp.psh { tcp_flags |= 0x08; }
            if tcp.ack { tcp_flags |= 0x10; }
            if tcp.urg { tcp_flags |= 0x20; }
            if tcp.ece { tcp_flags |= 0x40; }
            if tcp.cwr { tcp_flags |= 0x80; }

            (
                "ipv6",
                Ipv6Addr::from(v6.source).to_string(),
                Ipv6Addr::from(v6.destination).to_string(),
                v6.hop_limit,
                None,
                None,
                "tcp",
                Some(tcp.source_port),
                Some(tcp.destination_port),
                Some(tcp_flags),
                Some(tcp.window_size),
                mss,
                wscale,
                sack_ok,
                kinds,
            )
        }
        _ => return None, // Skip non-TCP packets for now
    };

    let ts_ns = (ts_sec as u128) * 1_000_000_000u128 + (ts_usec as u128) * 1_000u128;
    let meta = PktMeta {
        ts_ns,
        ts: Utc::now().to_rfc3339(),
        src_mac: format_mac(src_mac),
        dst_mac: format_mac(dst_mac),
        oui_vendor: oui_lookup_vendor(src_mac),
        l3,
        proto,
        src_ip,
        dst_ip,
        sport,
        dport,
        ttl_hop,
        ip_df,
        ip_id,
        flags,
        tcp_win,
        tcp_mss: mss,
        tcp_wscale: wscale,
        tcp_sack_ok: sack_ok,
        tcp_opts_hash: if opt_kinds.is_empty() {
            None
        } else {
            Some(hash_opts_kinds(&opt_kinds))
        },
        pkt_len,
        dir: "in",
        scan_id: None,
        probe_type: None,
        vantage: vantage.to_string(),
        iface: iface.to_string(),
        evidence_path: None, // fill when you decide to keep a micro-pcapng on triggers
    };

    Some(meta)
}

// --- IoT "spider" probe: SSDP (UPnP) M-SEARCH ---
fn probe_ssdp(interface_v4: Option<Ipv4Addr>) -> Result<()> {
    let sock = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))?;
    // Keep M-SEARCHs from leaving your L2 domain aggressively
    sock.set_multicast_ttl_v4(2)?;
    if let Some(ifip) = interface_v4 {
        // Hint the outgoing interface if needed
        let _ = sock.join_multicast_v4(&Ipv4Addr::new(239, 255, 255, 250), &ifip);
        // optional
    }
    let target = ("239.255.255.250", 1900);

    // Minimal but correct M-SEARCH
    let msg = concat!(
        "M-SEARCH * HTTP/1.1\r\n",
        "HOST: 239.255.255.250:1900\r\n",
        "MAN: \"ssdp:discover\"\r\n",
        "MX: 2\r\n",
        "ST: ssdp:all\r\n",
        "\r\n"
    );

    sock.send_to(msg.as_bytes(), target)?;
    Ok(())
}

// NDJSON Logger

pub fn log_artifact(data: serde_json::Value) {
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open("./.scans/netsniffer.ndjson")
        .unwrap();

    writeln!(file, "{}", serde_json::to_string(&data).unwrap()).unwrap();
}

// =====================================================================
// UNIFIED PIPELINE INTEGRATION - Source Trait Implementation
// =====================================================================

use crate::shared::shared::{ObsStream, Observation, ObservationKind};
use crate::shared::traits::Source;
use crate::plan::Plan;
use futures::stream::{self, StreamExt as FuturesStreamExt};

/// NetSniffer as a Source in the unified scanner pipeline
/// Provides passive network monitoring, OS fingerprinting, MAC vendor lookup
pub struct NetSnifferSource {
    interface: String,
    output_dir: PathBuf,
    max_packets: Option<usize>,  // Optional limit for testing
}

impl NetSnifferSource {
    pub fn new(interface: String, output_dir: PathBuf) -> Self {
        Self {
            interface,
            output_dir,
            max_packets: None,
        }
    }

    pub fn with_max_packets(mut self, max: usize) -> Self {
        self.max_packets = Some(max);
        self
    }

    /// Convert PktMeta to Observation for the pipeline
    fn pkt_to_observation(pkt: PktMeta, scan_id: uuid::Uuid) -> Vec<Observation> {
        let mut observations = Vec::new();
        let ts = chrono::Utc::now();

        // 1. Host Observation with MAC/Vendor/Passive OS hints
        let mut host_fields = serde_json::Map::new();
        host_fields.insert("ip".to_string(), pkt.src_ip.clone().into());
        host_fields.insert("mac_address".to_string(), pkt.src_mac.clone().into());

        if let Some(ref vendor) = pkt.oui_vendor {
            host_fields.insert("vendor".to_string(), vendor.clone().into());
        }

        // Passive OS detection hints from TTL
        host_fields.insert("ttl".to_string(), pkt.ttl_hop.into());
        if let Some(df) = pkt.ip_df {
            host_fields.insert("df_flag".to_string(), df.into());
        }
        if let Some(ip_id) = pkt.ip_id {
            host_fields.insert("ip_id".to_string(), ip_id.into());
        }

        // TCP fingerprint data for passive OS detection
        if let Some(tcp_win) = pkt.tcp_win {
            host_fields.insert("tcp_window".to_string(), tcp_win.into());
        }
        if let Some(mss) = pkt.tcp_mss {
            host_fields.insert("tcp_mss".to_string(), mss.into());
        }
        if let Some(wscale) = pkt.tcp_wscale {
            host_fields.insert("tcp_wscale".to_string(), wscale.into());
        }
        if let Some(sack) = pkt.tcp_sack_ok {
            host_fields.insert("tcp_sack_ok".to_string(), sack.into());
        }
        if let Some(opts_hash) = pkt.tcp_opts_hash {
            host_fields.insert("tcp_opts_hash".to_string(), opts_hash.to_string().into());
        }

        host_fields.insert("status".to_string(), "up".into());
        host_fields.insert("source".to_string(), "netsniffer".into());

        observations.push(Observation {
            scan_id,
            kind: ObservationKind::Host,
            fields: host_fields,
            ts,
            key: format!("host-{}", pkt.src_ip),
            raw: Some(serde_json::to_string(&pkt).unwrap_or_default()),
        });

        // 2. Service Observation if we have port information
        if let (Some(sport), Some(dport)) = (pkt.sport, pkt.dport) {
            let mut service_fields = serde_json::Map::new();
            service_fields.insert("ip".to_string(), pkt.src_ip.clone().into());
            service_fields.insert("port".to_string(), sport.into());
            service_fields.insert("protocol".to_string(), pkt.proto.into());
            service_fields.insert("state".to_string(), "open".into());
            service_fields.insert("source".to_string(), "netsniffer".into());

            if let Some(flags) = pkt.flags {
                service_fields.insert("tcp_flags".to_string(), flags.into());
            }

            observations.push(Observation {
                scan_id,
                kind: ObservationKind::Service,
                fields: service_fields,
                ts,
                key: format!("service-{}-{}-{}", pkt.src_ip, sport, pkt.proto),
                raw: None,
            });
        }

        // 3. Metric Observation for network statistics
        let mut metric_fields = serde_json::Map::new();
        metric_fields.insert("packet_length".to_string(), pkt.pkt_len.into());
        metric_fields.insert("protocol".to_string(), pkt.proto.into());
        metric_fields.insert("interface".to_string(), pkt.iface.into());
        metric_fields.insert("direction".to_string(), pkt.dir.into());

        observations.push(Observation {
            scan_id,
            kind: ObservationKind::Metric,
            fields: metric_fields,
            ts,
            key: "netsniffer-packet-stats".to_string(),
            raw: None,
        });

        observations
    }
}

#[async_trait::async_trait]
impl Source for NetSnifferSource {
    fn name(&self) -> &'static str {
        "netsniffer"
    }

    async fn start(&self, plan: &Plan) -> Result<ObsStream> {
        let scan_id = plan.scan_id;
        let interface = self.interface.clone();
        let output_dir = self.output_dir.clone();
        let max_packets = self.max_packets;

        // Ensure output directory exists
        create_dir_all(&output_dir)?;

        // Build BPF filter for scanner replies
        // This captures replies to our scanner (incoming traffic)
        let scanner_ip = ""; // TODO: Get local IP from interface
        let bpf_filter = format!(
            "tcp or udp or icmp"
        ); // Simplified for now, can be enhanced with dst host filtering

        log::info!("Starting NetSniffer on interface: {}, BPF: {}", interface, bpf_filter);

        // Open capture device
        let dev = if interface == "default" {
            Device::lookup()?.ok_or_else(|| anyhow!("no default capture device"))?
        } else {
            Device::list()?
                .into_iter()
                .find(|d| d.name == interface)
                .ok_or_else(|| anyhow!("interface {} not found", interface))?
        };

        let cap = Capture::from_device(dev)?
            .promisc(true)
            .timeout(100) // 100ms timeout for next()
            .buffer_size(8 << 20) // 8MB buffer for high-speed capture
            .open()?;

        // Create channel for packet communication between blocking and async contexts
        let (packet_tx, mut packet_rx) = tokio::sync::mpsc::unbounded_channel::<PacketInfo>();

        // Clone interface name for blocking task
        let interface_for_blocking = interface.clone();
        
        // Spawn blocking task for packet capture
        let cap_for_blocking = cap;
        tokio::task::spawn_blocking(move || {
            let mut cap = cap_for_blocking;
            if let Err(e) = cap.filter(&bpf_filter, true) {
                log::error!("Failed to set BPF filter: {}", e);
                return;
            }

            let mut packet_count: usize = 0;
            let mut last_heartbeat = std::time::Instant::now();
            let heartbeat_interval = std::time::Duration::from_secs(5);

            loop {
                // Check cancellation
                if engine_commands::is_scan_cancelled() {
                    log::info!("NetSniffer capture cancelled by user");
                    break;
                }

                // Check max packet limit
                if let Some(max) = max_packets {
                    if packet_count >= max {
                        log::info!("NetSniffer reached max packet limit: {}", max);
                        break;
                    }
                }

                // Capture next packet (blocking call)
                match cap.next_packet() {
                    Ok(packet) => {
                        packet_count += 1;
                        // Create packet info with minimal data needed
                        let packet_info = PacketInfo {
                            data: packet.data.to_vec(),
                            len: packet.header.len,
                            ts_sec: packet.header.ts.tv_sec,
                            ts_usec: packet.header.ts.tv_usec,
                        };
                        
                        if packet_tx.send(packet_info).is_err() {
                            // Receiver dropped, stream ended
                            log::debug!("Packet channel receiver dropped, stopping capture");
                            break;
                        }
                        last_heartbeat = std::time::Instant::now();
                    }
                    Err(pcap::Error::TimeoutExpired) => {
                        // Timeout is expected, check if we need to send heartbeat
                        let now = std::time::Instant::now();
                        if now.duration_since(last_heartbeat) >= heartbeat_interval {
                            // Send heartbeat signal (empty data)
                            if packet_tx.send(PacketInfo {
                                data: Vec::new(),
                                len: 0,
                                ts_sec: 0,
                                ts_usec: 0,
                            }).is_err() {
                                break;
                            }
                            last_heartbeat = now;
                        }
                        continue;
                    }
                    Err(e) => {
                        log::error!("NetSniffer capture error: {}", e);
                        // For fatal errors, break the loop
                        // For transient errors, continue
                        let error_str = format!("{}", e);
                        if error_str.contains("permission") || error_str.contains("memory") || error_str.contains("fatal") {
                            log::error!("Fatal capture error, stopping: {}", e);
                            break;
                        } else {
                            log::warn!("Transient capture error, continuing: {}", e);
                            continue;
                        }
                    }
                }
            }
            log::info!("NetSniffer blocking task completed");
        });

        // Create observation stream from channel
        let mut obs_queue = VecDeque::new();
        let mut packet_count: usize = 0;
        let mut last_heartbeat_time = std::time::Instant::now();
        let interface_for_stream = interface.clone();

        let stream = stream::unfold(
            (packet_rx, obs_queue, packet_count, last_heartbeat_time, interface_for_stream),
            move |(mut packet_rx, mut obs_queue, mut packet_count, mut last_heartbeat_time, interface_for_stream)| async move {
                // First, emit from observation queue if available
                if let Some(obs) = obs_queue.pop_front() {
                    return Some((obs, (packet_rx, obs_queue, packet_count, last_heartbeat_time, interface_for_stream)));
                }

                // Check cancellation
                if engine_commands::is_scan_cancelled() {
                    log::info!("NetSniffer stream cancelled by user");
                    let cancel_obs = Observation {
                        scan_id,
                        kind: ObservationKind::Metric,
                        fields: {
                            let mut fields = serde_json::Map::new();
                            fields.insert("status".to_string(), "cancelled".into());
                            fields
                        },
                        ts: chrono::Utc::now(),
                        key: "scan-status".to_string(),
                        raw: None,
                    };
                    return Some((cancel_obs, (packet_rx, obs_queue, packet_count, last_heartbeat_time, interface_for_stream)));
                }

                // Receive packet from channel with timeout
                match tokio::time::timeout(
                    tokio::time::Duration::from_millis(100),
                    packet_rx.recv()
                ).await {
                    Ok(Some(packet_info)) => {
                        // Check if this is a heartbeat signal (empty data)
                        if packet_info.data.is_empty() {
                            // Emit heartbeat observation
                            let heartbeat_obs = Observation {
                                scan_id,
                                kind: ObservationKind::Metric,
                                fields: {
                                    let mut fields = serde_json::Map::new();
                                    fields.insert("status".to_string(), "listening".into());
                                    fields.insert("packet_count".to_string(), packet_count.into());
                                    fields
                                },
                                ts: chrono::Utc::now(),
                                key: "netsniffer-heartbeat".to_string(),
                                raw: None,
                            };
                            return Some((heartbeat_obs, (packet_rx, obs_queue, packet_count, last_heartbeat_time, interface_for_stream)));
                        }

                        packet_count += 1;

                        // Parse packet to PktMeta using timestamp and length directly
                        if let Some(pkt_meta) = handle_packet_with_ts(
                            &packet_info.data,
                            packet_info.ts_sec,
                            packet_info.ts_usec,
                            packet_info.len,
                            "scanner",
                            &interface_for_stream
                        ) {
                            // Convert to observations (may return multiple: Host, Service, Metric)
                            let observations = Self::pkt_to_observation(pkt_meta, scan_id);

                            // Log to NDJSON file
                            for obs in &observations {
                                if let Ok(json_str) = serde_json::to_string(obs) {
                                    log_artifact(serde_json::from_str(&json_str).unwrap_or(json!({})));
                                }
                            }

                            // Queue all observations for emission
                            for obs in observations {
                                obs_queue.push_back(obs);
                            }

                            // Emit first observation from queue
                            if let Some(obs) = obs_queue.pop_front() {
                                return Some((obs, (packet_rx, obs_queue, packet_count, last_heartbeat_time, interface_for_stream)));
                            }
                        }

                        // No valid observation, emit progress metric
                        let progress_obs = Observation {
                            scan_id,
                            kind: ObservationKind::Metric,
                            fields: {
                                let mut fields = serde_json::Map::new();
                                fields.insert("packet_count".to_string(), packet_count.into());
                                fields
                            },
                            ts: chrono::Utc::now(),
                            key: "netsniffer-progress".to_string(),
                            raw: None,
                        };
                        Some((progress_obs, (packet_rx, obs_queue, packet_count, last_heartbeat_time, interface_for_stream)))
                    }
                    Ok(None) => {
                        // Channel closed, capture task ended
                        log::info!("NetSniffer packet channel closed");
                        None
                    }
                    Err(_) => {
                        // Timeout waiting for packet, emit heartbeat if needed
                        let now = std::time::Instant::now();
                        if now.duration_since(last_heartbeat_time) >= std::time::Duration::from_secs(5) {
                            last_heartbeat_time = now;
                            let heartbeat_obs = Observation {
                                scan_id,
                                kind: ObservationKind::Metric,
                                fields: {
                                    let mut fields = serde_json::Map::new();
                                    fields.insert("status".to_string(), "listening".into());
                                    fields.insert("packet_count".to_string(), packet_count.into());
                                    fields
                                },
                                ts: chrono::Utc::now(),
                                key: "netsniffer-heartbeat".to_string(),
                                raw: None,
                            };
                            Some((heartbeat_obs, (packet_rx, obs_queue, packet_count, last_heartbeat_time, interface_for_stream)))
                        } else {
                            // Continue waiting
                            Some((
                                Observation {
                                    scan_id,
                                    kind: ObservationKind::Metric,
                                    fields: {
                                        let mut fields = serde_json::Map::new();
                                        fields.insert("status".to_string(), "waiting".into());
                                        fields.insert("packet_count".to_string(), packet_count.into());
                                        fields
                                    },
                                    ts: chrono::Utc::now(),
                                    key: "netsniffer-waiting".to_string(),
                                    raw: None,
                                },
                                (packet_rx, obs_queue, packet_count, last_heartbeat_time, interface_for_stream),
                            ))
                        }
                    }
                }
            },
        );

        Ok(Box::pin(stream))
    }
}
