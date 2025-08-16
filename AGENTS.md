# LEGION2 Development Guide

## Overview
LEGION2 uses a unified streaming pipeline built around three core traits:
`Source`, `Transform`, and `Sink`. A single `Observation` type flows through
this pipeline. The `Engine` orchestrator, in tandem with the `Registry`, wires
modules together and exposes one command to the frontend:

```rust
engine_execute(plan)
```

## Runtime Flow

```
Plan → Registry → Engine {
  Source (masscan/nmap)
  → CompositeTransform {
      → IpEnrichmentTransform
      → ServiceParsingTransform
      → ProgressTrackingTransform
  }
  → Broadcaster
  → Sinks (UI + Database)
}
```

- The **MasscanSource** reads stdout and converts data into
  `Observation::ServiceFound` events.
- **UiSink** emits Tauri events (`obs:host`, `obs:service`).
- **DbSink** persists observations via a minimal encrypted SQLite wrapper
  (`rusqlite` only, injected as `Arc<Db>`).

## Repository Layout

### Rust backend (`src-tauri/`)
- `main.rs` – Tauri setup and dependency injection
- `database.rs` – SQLite abstraction layer
- `plan.rs` – plan builder used by `engine_execute`
- `core/` – engine, registry, traits, transforms, and sink implementations
- `scanning/` – masscan & nmap sources and related models
- `analysis/` – vulnerability and correlation engines (WIP)
- `commands/` – Tauri command handlers
- `utils/` – helpers (network, parsing, streaming)
- Logs are written to `src-tauri/.logs/.logs.log`

### React frontend (`src/`)
- `App.tsx` mounts a single `ScannerPanel`
- Components: `ScanForm`, `ScanProgress`, `HostTable`, `NetworkMap`,
  `ResultViewer`
- Services: `tauriApi.ts`, `legionService.ts`
- Stores: `appStore.ts`, `hostStore.ts` (should remain thin—listen for backend
  events and forward `engine_execute` commands)

### Docs & Cheatsheets
- CLI notes and usage examples live in `docs/massnmap.md`

## Key Features
Implemented:
1. Network scanning with Masscan/Nmap and real-time output
2. Host & service discovery with database persistence
3. Event-driven UI via Tauri events
4. Cross-platform builds with bundled binaries

Planned:
1. Vulnerability analysis & correlation
2. Attack path generation
3. Plugin system for additional scanners/analysers

## Data Flow
```
Frontend → Tauri command (`engine_execute`) → Registry
    → Sources → Transforms → Broadcaster
    → {UiSink, DbSink}
      ↓           ↓
   UI events   SQLite storage
```

## Contribution Tips
- Use the existing pipeline architecture; new modules should implement the
  `Source`, `Transform`, or `Sink` traits and register via the `Registry`.
- When touching database code, ensure the `Db` wrapper remains the single access
  point and stays encrypted.
- For network utilities, note that `Ipv4Net::broadcast()` returns `Ipv4Addr` (no
  `Option`).
- Run `cargo test` for backend changes and `npm test` for frontend work.
- Keep frontend stores minimal—backend already handles progress tracking and
  event management.

