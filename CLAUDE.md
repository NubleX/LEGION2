Overview

LEGION2 is an alpha-stage network‑security scanner built on a modern stack:

    Frontend: React 18 + TypeScript

    Backend: Rust with Tauri

    Persistence: SQLite

    Scanning Engine: nmap/masscan with real‑time output

    Communication: event‑driven updates between frontend and backend

The repository root separates the new code from legacy artifacts. The active code lives mainly in src (React frontend) and src-tauri (Rust backend), while legacy-* folders retain earlier Python components for reference

.
Key Components
Rust backend (src-tauri)

    Application entrypoint – main.rs initializes the SQLite database, event streamer, scan coordinator, and wires Tauri commands for UI interaction

.

Scan orchestration – ScanCoordinator tracks active scans, delegates work to nmap or masscan scanners, and streams progress events

.

nmap integration – NmapScanner structures scan results and dynamically builds nmap commands for different scan types

.

Database layer – database.rs defines the normalized schema for hosts, ports, and vulnerabilities, ensuring foreign‑key relationships and indexes

.

Processing pipeline – The core module exposes Source, Transform, and Sink traits, enabling plug‑and‑play data flows through a plan-driven engine

.

Event streaming – shared.rs provides a lightweight EventStreamer so the backend can push real‑time scan events to subscribers

.

Future analysis – analysis/engine.rs sketches a vulnerability and correlation engine that reacts to discovered hosts/services and emits findings back to the UI

    .

React frontend (src)

    Entry point – App.tsx mounts a single ScannerPanel component for the entire UI

.

Scanner panel – Presents the dashboard, hosts/results views, and invokes backend commands to launch scans and fetch data

.

State management – A Zustand store (appStore.ts) listens to Tauri events (obs:*) for hosts, services, progress, metrics, and errors, keeping the UI reactive to backend updates

    .

Suggestions for Further Study

    Scanning Plans & Pipelines – Explore plan.rs, core/engine.rs, and the modules directory to understand how sources, transforms, and sinks compose complex scan workflows.

    Masscan & Other Sources – The scanning subsystem also includes masscan.rs and placeholders for additional tools; extending these demonstrates how new sources fit the pipeline.

    Analysis Modules – The analysis module (vulnerability correlation, attack‑path generation) is in early stages; contributing here requires familiarity with graph/analysis algorithms.

    Frontend Expansion – Review additional components like NetworkMap, HostTable, and ResultViewer for UI patterns; consider adding new views or filters once the state store APIs are clear.

    Event Streaming & Persistence – Dive deeper into EventStreamer and DatabaseOperations to see how observations flow from scanners into the SQLite store and up to the UI.

Understanding Tauri’s command architecture, Rust async patterns (Tokio), nmap/masscan command-line options, and state-driven React UIs will help new contributors move quickly.