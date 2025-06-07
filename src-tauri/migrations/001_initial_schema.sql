CREATE TABLE projects (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT,
    created_at TIMESTAMP NOT NULL,
    updated_at TIMESTAMP NOT NULL
);

CREATE TABLE hosts (
    id TEXT PRIMARY KEY,
    ip TEXT NOT NULL UNIQUE,
    hostname TEXT,
    mac_address TEXT,
    vendor TEXT,
    os_name TEXT,
    os_family TEXT,
    os_accuracy REAL,
    status TEXT NOT NULL DEFAULT 'unknown',
    created_at TIMESTAMP NOT NULL,
    updated_at TIMESTAMP NOT NULL
);

CREATE TABLE ports (
    id TEXT PRIMARY KEY,
    host_id TEXT NOT NULL,
    number INTEGER NOT NULL,
    protocol TEXT NOT NULL,
    state TEXT NOT NULL,
    service TEXT,
    version TEXT,
    banner TEXT,
    created_at TIMESTAMP NOT NULL,
    FOREIGN KEY (host_id) REFERENCES hosts (id) ON DELETE CASCADE
);

CREATE TABLE scans (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    targets TEXT NOT NULL,
    scan_type TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'queued',
    progress REAL NOT NULL DEFAULT 0.0,
    start_time TIMESTAMP NOT NULL,
    end_time TIMESTAMP,
    created_at TIMESTAMP NOT NULL
);

CREATE TABLE vulnerabilities (
    id TEXT PRIMARY KEY,
    host_id TEXT NOT NULL,
    port_id TEXT,
    name TEXT NOT NULL,
    severity TEXT NOT NULL,
    description TEXT NOT NULL,
    cvss_score REAL,
    references TEXT,
    discovered_at TIMESTAMP NOT NULL,
    FOREIGN KEY (host_id) REFERENCES hosts (id) ON DELETE CASCADE,
    FOREIGN KEY (port_id) REFERENCES ports (id) ON DELETE SET NULL
);

CREATE TABLE scripts (
    id TEXT PRIMARY KEY,
    host_id TEXT NOT NULL,
    port_id TEXT,
    name TEXT NOT NULL,
    output TEXT NOT NULL,
    executed_at TIMESTAMP NOT NULL,
    FOREIGN KEY (host_id) REFERENCES hosts (id) ON DELETE CASCADE,
    FOREIGN KEY (port_id) REFERENCES ports (id) ON DELETE SET NULL
);

CREATE INDEX idx_hosts_ip ON hosts(ip);
CREATE INDEX idx_ports_host_id ON ports(host_id);
CREATE INDEX idx_ports_number ON ports(number);
CREATE INDEX idx_vulns_host_id ON vulnerabilities(host_id);
CREATE INDEX idx_vulns_severity ON vulnerabilities(severity);