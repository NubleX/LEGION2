# Engine and Proxy Decision Record

Status: decided 2026-11-06 (v0.4.1). Scope of this document is *direction*, not
implementation. No engine or proxy code ships in 0.4.1.

This record answers four recurring questions: should we integrate a Rust nmap
port (#4-equivalent), is tun2socks feasible (#55), are nmap + masscan too many
dependencies for a bespoke engine ("SPIDERIOTA", #46, #39), and should we merge
a native scanner with proxy support and NSE (#43, #44, #45).

---

## 1. Is there a Rust nmap we can embed? No.

- **RustScan** (GPL-3.0, bee-san/RustScan) is binary-only: its `Cargo.toml`
  declares a `[[bin]]` and no `[lib]`, so it cannot be consumed as a crate. It
  still shells out to the external `nmap` binary for service/version detection.
  Integrating it would add a *third* external binary to do what masscan already
  does (fast port discovery), with no library API. **Verdict: do not integrate.**
- No Rust crate reimplements nmap's scanning. The crates that exist
  (`nmap_xml_parser`, `rust_nmap`, `parsenmap`) only parse nmap XML - which we
  already do natively in `src-tauri/src/utils/xml_parser.rs`.
- No standard Rust crate runs NSE (Lua) scripts. Embeddable Lua exists (`mlua`,
  `lua-src`), but the NSE *script corpus* and its libraries are nmap's.

## 2. The real constraint on dropping nmap: licensing, not effort

nmap's service/version detection is driven by `nmap-service-probes`, licensed
under the **Nmap Public Source License (NPSL)**, not GPL. A bespoke engine that
bundled or derived from that probe database inside this GPL-3 project is a
licensing problem, not merely a lot of work. Any own-engine path **must build
its own probe corpus** or adopt an Apache/BSD-licensed alternative. This is the
single most important fact for the SPIDERIOTA question.

## 3. zgrab2 is the credible path to replace nmap `-sV`

`zmap/zgrab2` (Go, **Apache-2.0**) is a modular L7 banner/handshake grabber with
modules for http, tls, ssh, modbus, mqtt and more. Clean-licensed and
scriptable, it is the realistic way to get service/version fingerprinting
*without the NPSL entanglement*. Path: subprocess first, native Rust port of the
modules we need later. Note zgrab2#568 confirms nmap already does IoT probing
well - zgrab2's value here is the licence and the module model, not raw
capability. Our own `src-tauri/src/scanners/iot_probe_source.rs` (SSDP, mDNS,
WSDD, SNMP, CoAP over UDP; MQTT over TCP) is already the Rust-native seed of this
fingerprinting layer.

## 4. Proxy / SOCKS5 (#55): SOCKS5 in our own scanner, NOT a TUN engine

The #55 premise - "route scans through a SOCKS5 proxy to avoid the
`cap_net_raw` privilege" - is half right and must be corrected:

- A SOCKS5 proxy carries only **TCP CONNECT** and **UDP ASSOCIATE**. It cannot
  carry raw IP, crafted SYN, ICMP or ARP. Through a proxy you get exactly a TCP
  connect scan (`-sT`), which **already needs no privilege**. So a proxy is an
  **egress / anonymity** feature (scan through Mullvad), not a way to do
  privileged scan types unprivileged.
- A userspace **TUN** stack (tun2proxy, ipstack, smoltcp) *could* let us craft
  SYN without raw sockets - but creating a TUN device needs **`CAP_NET_ADMIN`**,
  which is strictly *broader* than `cap_net_raw`, plus a privileged helper and
  per-platform lifecycle code (tun0 / utun / wintun). That is **more** privilege
  than today, not less.

**Decision:** implement SOCKS5 egress inside LEGION2's own connect-scanner
(native Rust, `tokio` + a socks client), so the connect-scan path can be routed
through a local SOCKS5 proxy on Linux, macOS and Windows with zero new
privilege. **Do not** port the ID-Spoofer `tun2socks` backend into LEGION2.
tun2socks remains ID-Spoofer's concern (whole-system tunnelling); LEGION2 only
needs per-scan SOCKS5 egress.

## 5. Cross-platform reality check (why the nmap dependency hurts)

`src-tauri/src/os.rs` already resolves per-platform bundled binaries
(`nmap-x86_64-pc-windows-msvc.exe`, `masscan-...`) with a PATH fallback, but no
release ships those binaries and the README targets Linux only. So today on
Windows/macOS the app depends entirely on whatever `nmap`/`masscan` the user has
on PATH. A native Rust discovery sweeper removes that dependency for the most
common path (host + port discovery) and is the first concrete step toward
cross-platform support.

## 6. L2 / Wi-Fi and ICS references (roadmap, not now)

- **AntiGoblin, esp32-mac-collector** - L2 / Wi-Fi-side MAC and device
  collection, hardware-assisted. This is a *new discovery Source* behind
  `src-tauri/src/shared/traits.rs::Source` (alongside nmap, masscan, netsniffer,
  iot_probe), not an nmap replacement, and it feeds ID-Spoofer. Its own project.
- **i5-modbus-scan, CryptoComm-Auditor, openhab-addons** - protocol references
  for new native probes (Modbus, MQTT topics, CoAP resources). openhab-addons is
  a large Java binding set: mine it for protocol detail, do not take it as a
  dependency. Modbus belongs as a zgrab2-style L7 module / native probe.

## 7. Competitive frame and the staged plan

runzero is the benchmark: unauthenticated asset inventory via L2 + L7
fingerprinting, no nmap. The coherent, staged LEGION2 path:

1. **Native Rust discovery sweeper** as a new `Source`, replacing masscan for
   host + port discovery (drops one external binary). No NPSL issue - discovery
   is just connect/SYN, no probe corpus.
2. Grow `iot_probe_source` + **zgrab2-style L7 modules** into the SPIDERIOTA
   fingerprint engine (Apache-licensed corpus, no NPSL).
3. Keep **nmap optional** for `-O` and NSE until the native corpus is credible.
4. **SOCKS5 egress** in the native scanner for anonymised scanning (§4).
5. L2 / Wi-Fi discovery Source (§6) as a parallel track feeding ID-Spoofer.

This is multi-release work and is **not** started in 0.4.1. 0.4.1 ships the
AppImage fix, the topology/live-output/liveness regression fixes, and the
dead-code removal only.
