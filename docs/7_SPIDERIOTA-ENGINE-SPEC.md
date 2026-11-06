# SPIDERIOTA Native Engine - Specification for the Next Major Build

Status: draft spec for the next major version (targeting v0.5.x -> v1.0). Supersedes
and expands `docs/6_ENGINE-DECISION.md`. This is the design contract for making
LEGION2 a single self-contained binary with **zero external scanner dependencies**.

---

## 1. Goal and principles

Replace the external-binary scanning stack (nmap, masscan) and the nmap-mediated
NSE scripting with a **native Rust engine compiled into the LEGION2 binary**. After
this build, a full scan of a network - host discovery, port scanning, service and
version detection, OS fingerprinting, IoT/OT protocol discovery, scripted probes,
and vulnerability correlation - runs with **no subprocess, no bundled third-party
binary, and no NPSL/GPL-incompatible data**.

Principles:

1. **No external scanner binaries.** No nmap, masscan, or shelling out for scan
   logic. (The OS's own `ip`/`getcap`/`pkexec` for capability setup are allowed;
   they are not scanners.)
2. **Clean licensing.** Every probe signature, fingerprint and script we ship is
   ours or under a GPL-3-compatible permissive licence (Apache-2.0, MIT, BSD, 0BSD).
   No nmap-service-probes, no NSE scripts, no NASL, no nmap-os-db derivatives - those
   are NPSL and cannot live in a GPL-3 project. See section 9.
3. **Cross-platform by construction.** Pure-Rust paths that work on Linux, macOS and
   Windows without per-platform bundled executables.
4. **Privilege-aware, degrade gracefully.** Unprivileged connect/UDP scanning is the
   default and needs no capabilities; raw SYN/ARP/ICMP is an opt-in fast path gated
   on `cap_net_raw` or root. The UI always states which mode is active (builds on the
   euid/cap work already in `os.rs`).
5. **One observation bus.** Everything is a `Source` emitting `Observation`s through
   the existing `Transform` -> `Sink` pipeline into the single plaintext SQLite store.
   No new parallel data path.

---

## 2. What we keep, what we replace

**Keep (the spine already works):**

- `shared/traits.rs`: `Source`, `Transform`, `Sink`.
- The `Observation` model and the broadcast bus (`core/engine.rs`, `core/sinks.rs`).
- Plaintext queryable SQLite storage (`database.rs`) and the Db/Ui/Vuln sinks.
- The enrichment transforms (MAC-vendor, OS hints, service parse, CVE correlation).
- The native IoT probe source (`scanners/iot_probe_source.rs`) - this is the seed of
  the new engine and expands, it does not get replaced.

**Replace (remove the external dependency):**

| Today (external) | Next (native Source) |
| --- | --- |
| nmap `-sn` host discovery | `discovery` engine (ARP / ICMP / TCP-UDP sweep) |
| masscan port sweep | `portscan` engine (async connect + optional raw SYN) |
| nmap `-sV` service/version | `fingerprint` engine (probe DB + protocol handshakes) |
| nmap `-O` OS detection | native OS fingerprint (TTL / TCP options / ICMP) |
| nmap NSE (`--script`) | native probe plugins + optional embedded Lua for OUR scripts |
| bundled `.nse` / `.lua` / `nasl` corpus | removed (NPSL); replaced by our signature DB |

During transition, nmap/masscan remain available behind a feature flag and a config
toggle as fallback Sources, so the native path can be validated against them before
they are deleted (section 10).

---

## 3. Architecture

Each native capability is a `Source` (or a small set of them) behind the existing
trait, so the engine, transforms, sinks, DB and UI are unchanged:

```
Sources (native):
  discovery  ─┐
  portscan   ─┤
  fingerprint─┤→ ObsStream → Transform pipeline → Broadcast → {UiSink, DbSink, VulnSink}
  iot_probe  ─┤
  l2_wifi    ─┘   (SOCKS5 egress wraps the connect paths)
```

New module layout (under `src-tauri/src/engine/`, native, no external calls):

- `engine/discovery/` - host liveness.
- `engine/portscan/` - TCP/UDP port state.
- `engine/fingerprint/` - service/version + OS.
- `engine/script/` - the scripting/probe runtime (NSE replacement).
- `engine/proto/` - one module per application/OT protocol prober.
- `engine/signatures/` - the data-driven signature/probe database (loaded at runtime).
- `engine/net/` - shared raw-socket / connect / SOCKS5 primitives and privilege gating.

---

## 4. Native components

### 4.1 Discovery engine (`engine/discovery`)
Determine which hosts are alive, honestly (reason-backed, never "-Pn user-set").
- **Local segment:** ARP request/reply (needs `cap_net_raw`); fastest and definitive
  for L2. Also populates MAC/vendor for free.
- **Routed / unprivileged:** TCP SYN-or-connect to a small common-port set, ICMP echo
  where permitted, UDP probes to common services. A host is "up" only with a real
  response or an open port - the same evidence rule now enforced in `xml_parser.rs`
  becomes the engine's native contract.
- Output: `Observation{kind: Host, status, status_reason, mac?, vendor?}`.

### 4.2 Port scan engine (`engine/portscan`)
- **Default (no privilege):** async `tokio` connect scan with bounded concurrency and
  adaptive timeout; real open/closed/filtered per port. Replaces masscan for the
  common case and `-sT` for nmap.
- **Fast path (privileged):** raw SYN scan via `socket2`/`pnet` with our own TCP/IP
  packet build + a pcap/AF_PACKET receive loop, rate-limited. Gated on `cap_net_raw`.
- **UDP:** protocol-aware payloads (reuse `engine/proto`) so UDP services actually
  answer instead of looking filtered.
- Output: `Observation{kind: Service, port, state, reason}` with `reason` a real
  signal (syn-ack, connect-ok, icmp-port-unreach, ...).

### 4.3 Fingerprint engine (`engine/fingerprint`)
Service, version and OS detection without nmap-service-probes.
- **Banner + probe matching:** send protocol-appropriate probes, match responses
  against our signature DB (section 5). Clean-room signatures, not nmap's.
- **TLS:** native handshake (`rustls`) for cert/SNI/ALPN/JA3-style fingerprints.
- **OS fingerprint:** passive (TTL, TCP window/options from `etherparse`) and light
  active (handful of crafted probes) producing a confidence-scored guess. Builds on
  the TTL/OS-hint logic already in `core/transformer.rs`.
- Output: enriches existing Host/Service observations with product/version/os fields.

### 4.4 Scripting / probe runtime (`engine/script`) - the NSE replacement
Two tiers, neither depending on nmap or its NPSL corpus:
- **Native probe plugins (Rust):** a `Probe` trait (name, match criteria by
  port/service/protocol, async `run(target) -> Vec<Finding>`). Fast, type-safe, no
  interpreter. This is the primary mechanism and where security-sensitive checks live.
- **Embedded Lua (optional, `mlua`, MIT):** runs **our own** scripts (clean-licensed,
  shipped under `engine/signatures/scripts/`) for community-contributed checks. `mlua`
  gives a sandboxed Lua 5.4 VM with a curated host API (http, tls, socket, dns, json,
  match helpers) - a deliberate, minimal re-imagining of nselib, written by us. We do
  **not** import or translate nmap's NSE scripts.
- CVE extraction from probe/script output feeds `VulnSink` as it does today.

### 4.5 IoT / OT protocol suite (`engine/proto`)
Expand `iot_probe_source.rs` into a first-class, data-driven protocol prober. Each
protocol is a module exposing: discovery payload, response parser, and service/vendor
mapping.
- **Already native:** SSDP (1900), mDNS/DNS-SD (5353), WS-Discovery (3702), SNMP (161),
  CoAP (5683/5684), MQTT (1883/8883).
- **Add (consumer/IoT):** UPnP device/service walk, LLMNR (5355), NetBIOS-NS (137),
  AMQP (5672), Redis (6379), ONVIF/RTSP (cameras), Zeroconf service enumeration.
- **Add (industrial/OT, high value, clean protocol specs):** Modbus/TCP (502),
  BACnet/IP (47808), DNP3 (20000), Siemens S7comm (102), EtherNet/IP + CIP (44818/2222),
  OPC-UA (4840). Protocol references (not code dependencies) come from open specs and
  from reading - not vendoring - projects like `openhab-addons`.
- Mandatory: read-only, identification-only probes by default (no writes to OT devices
  without an explicit, clearly-labelled opt-in) - this is safety-critical for ICS.

### 4.6 L2 / Wi-Fi discovery source (`engine/l2_wifi`, optional hardware)
Hardware-assisted discovery feeding the same bus (and ID-Spoofer): collect MACs and
device hints from the Wi-Fi/L2 side (the AntiGoblin / esp32-mac-collector direction).
A separate, optional `Source`; not required for the core native engine.

### 4.7 SOCKS5 egress (`engine/net`)
Route the connect-scan and L7 probe paths through a local SOCKS5 proxy (scan through
Mullvad/VPN) natively in Rust - no TUN device, no `CAP_NET_ADMIN`, works on all three
OSes. Raw SYN/ARP cannot traverse SOCKS5 (documented limitation from the decision
record); proxy mode therefore implies the unprivileged connect path.

---

## 5. Signature / probe database (`engine/signatures`)

- **Format:** data-driven, versioned files (TOML/JSON/RON) loaded at runtime, so
  signatures update without recompiling. Schema: match conditions (port, transport,
  probe payload, response regex/bytes) -> {service, product, version capture, cpe?}.
- **Provenance:** every entry is ours or permissively licensed. Seed from observed
  banners, open protocol specs, and permissive datasets; never from
  nmap-service-probes, nmap-os-db, or NSE. Keep a `PROVENANCE.md` per dataset.
- **OS DB:** TTL + TCP-options + ICMP quirks table, clean-room.
- Ship a small high-value core corpus first (top ~200 services), grow over releases.

---

## 6. Privilege and capability model

- Detect `euid == 0` and the LEGION2 binary's own `cap_net_raw` (already in `os.rs`).
- **No capability:** connect/UDP scanning, L7 probes, TLS, SOCKS5 - fully functional.
- **With `cap_net_raw`:** ARP discovery, raw SYN, custom ICMP - the fast/low-level path.
- The in-app grant already sets caps on the legion2 binary; once scanning is native,
  that single grant unlocks everything (no more per-tool nmap/masscan caps).
- Windows: raw sockets via Npcap when present; otherwise connect-scan path.

---

## 7. Data model and reporting

- Storage stays the single plaintext SQLite DB in the stable per-user dir
  (`~/.local/share/legion2`), queryable and indexable.
- **Reporting layer (new):** a report generator that queries the DB and emits
  structured output - JSON and CSV for machines, and a templated HTML report
  (printable to PDF) for humans: executive summary, host inventory, service matrix,
  vulnerability findings with CVE/CVSS, topology snapshot. This is the end-goal the
  plaintext-storage decision was made to enable.
- If at-rest encryption is later required, add it at the whole-file layer (SQLCipher)
  without touching queries. Analytical reporting over very large scans may move to an
  embedded columnar engine (DuckDB) behind the same SQL - neither is in this build.

---

## 8. Dependency budget (all permissive, GPL-3-compatible)

Allowed native crates (indicative): `tokio`, `socket2`, `pnet`/`pnet_packet` (MIT),
`etherparse` (0BSD/MIT), `pcap` (where raw receive is needed), `rustls` (TLS),
`hickory-dns`/`trust-dns` (mDNS/DNS-SD), `mlua` (MIT, scripting), `serde` + a format
crate for signatures, `ipnet`, `rand`. No GPL-incompatible or NPSL data. Every added
crate's licence is checked into `docs/THIRD_PARTY_LICENSES.md`.

---

## 9. Licensing cleanup (do this early)

The repo currently vendors nmap's NSE corpus under
`src-tauri/src/scanners/probes/nse-scripts/`, `nse-lib/`, and NASL content under
`nasl/`. These are NPSL / mixed and are a licensing liability in a GPL-3 project.
- Remove them once the native scripting runtime and signature DB cover the needed
  checks, and never ship nmap-derived signatures.
- Until removed, do not treat them as our capability; they only function via an
  external nmap and must not be redistributed as part of LEGION2's own engine.

---

## 10. Phasing and milestones

Incremental, each milestone shippable and validated against the current external tools
before anything is deleted:

- **M1 - Native discovery + connect port scan** as Sources behind a feature flag.
  Validate host/port parity against nmap `-sn` + masscan on a known /24. Honest
  liveness by construction.
- **M2 - Native fingerprint engine + core signature DB** (top services) and native OS
  hints. Validate `-sV`-level output on common services.
- **M3 - Protocol suite expansion** (OT/ICS: Modbus, BACnet, DNP3, S7comm, EtherNet/IP;
  plus UPnP/ONVIF/Redis/AMQP). Read-only by default.
- **M4 - Scripting runtime** (`Probe` trait + `mlua` sandbox) with an initial set of
  our own scripts and CVE extraction. This is the formal NSE replacement.
- **M5 - Raw SYN fast path + SOCKS5 egress**, privilege-gated.
- **M6 - Reporting layer** (JSON/CSV/HTML->PDF).
- **M7 - Remove nmap, masscan, and the NPSL corpus.** Delete the external Sources, the
  bundled binaries, and `nse-scripts`/`nse-lib`/`nasl`. The binary is now self-contained.
  This milestone is the version bump to v1.0.

---

## 11. Non-goals and risks

- **Not** a from-scratch Lua ecosystem clone - `mlua` runs our scripts, we do not
  reimplement nselib wholesale.
- **Risk - signature coverage:** nmap's probe DB is huge; our clean corpus starts
  small. Mitigate by prioritising the top services and OT protocols, and by keeping
  nmap as an optional fallback until M7.
- **Risk - raw-socket portability:** Windows raw sockets are restricted; Npcap or the
  connect path covers it. macOS BPF needs entitlement/root; connect path is the
  default there.
- **Risk - OT safety:** probing industrial devices can disrupt them. Default to
  passive/read-only identification; gate any active OT write behind an explicit,
  audited opt-in.
- **Risk - scope:** this is multi-release. Each milestone must stand on its own and not
  regress the shipping v0.4.x pipeline.

---

## 12. Acceptance criteria (definition of done for v1.0)

1. A full scan (discovery -> ports -> services/version -> OS -> IoT/OT probes ->
   scripted checks -> vuln correlation) of a /24 completes with **no external scanner
   binary present on the system** (verify in a container with nmap/masscan absent).
2. Host liveness is always evidence-backed; no phantom "up" hosts.
3. Works on Linux, macOS and Windows: unprivileged by default, privileged fast path
   when capabilities are granted.
4. The repository contains **no NPSL/GPL-incompatible scan data**; `grep` for
   nmap-service-probes / NSE / NASL signatures returns nothing shipped.
5. A scan produces a structured report (JSON/CSV/HTML) directly from the DB.
6. Scanning through a SOCKS5 proxy works end-to-end on the connect path.
