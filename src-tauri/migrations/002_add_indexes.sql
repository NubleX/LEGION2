CREATE INDEX IF NOT EXISTS idx_hosts_vulnerability_count ON hosts(vulnerability_count);
CREATE INDEX IF NOT EXISTS idx_ports_service ON ports(service);