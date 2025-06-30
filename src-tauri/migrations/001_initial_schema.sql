-- Initial schema for LEGION2
CREATE TABLE IF NOT EXISTS hosts (
    id TEXT PRIMARY KEY,
    ip TEXT NOT NULL,
    hostname TEXT,
    mac_address TEXT,
    vendor TEXT,
    os_name TEXT,
    os_family TEXT,
    os_accuracy REAL,
    status TEXT NOT NULL DEFAULT 'unknown',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS ports (
    id TEXT PRIMARY KEY,
    host_id TEXT NOT NULL,
    number INTEGER NOT NULL,
    protocol TEXT NOT NULL,
    state TEXT NOT NULL,
    service TEXT,
    version TEXT,
    banner TEXT,
    created_at TEXT NOT NULL,
    FOREIGN KEY (host_id) REFERENCES hosts(id)
);

CREATE TABLE IF NOT EXISTS vulnerabilities (
    id TEXT PRIMARY KEY,
    host_id TEXT NOT NULL,
    port_id TEXT,
    name TEXT NOT NULL,
    severity TEXT NOT NULL,
    description TEXT NOT NULL,
    cvss_score REAL,
    references TEXT,
    discovered_at TEXT NOT NULL,
    FOREIGN KEY (host_id) REFERENCES hosts(id),
    FOREIGN KEY (port_id) REFERENCES ports(id)
);

CREATE TABLE IF NOT EXISTS projects (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS scans (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    targets TEXT NOT NULL,
    scan_type TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'queued',
    progress REAL NOT NULL DEFAULT 0.0,
    start_time TEXT NOT NULL,
    end_time TEXT,
    created_at TEXT NOT NULL
);

-- Indexes for better performance
CREATE INDEX IF NOT EXISTS idx_hosts_ip ON hosts(ip);
CREATE INDEX IF NOT EXISTS idx_hosts_status ON hosts(status);
CREATE INDEX IF NOT EXISTS idx_ports_host_id ON ports(host_id);
CREATE INDEX IF NOT EXISTS idx_ports_number ON ports(number);
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_host_id ON vulnerabilities(host_id);
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_severity ON vulnerabilities(severity);