use serde::Serialize;
use std::net::Ipv4Addr;

#[derive(Debug, Clone, Serialize)]
pub struct HostResult {
    pub ip: Ipv4Addr,
    pub mac: String,
    pub vendor: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub open_ports: Vec<u16>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScanReport {
    pub interface: String,
    pub target_network: String,
    pub hosts: Vec<HostResult>,
    pub total_found: usize,
}
