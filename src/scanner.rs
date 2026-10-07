use crate::cli::Cli;
use anyhow::{Context, Result, bail};
use comfy_table::modifiers::UTF8_ROUND_CORNERS;
use comfy_table::presets::UTF8_FULL;
use comfy_table::{Cell, Color, Row, Table};
use pnet::datalink::{self, MacAddr, NetworkInterface};
use pnet::packet::Packet;
use pnet::packet::arp::{ArpHardwareTypes, ArpOperations, ArpPacket, MutableArpPacket};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
use serde::Serialize;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::sync::{Semaphore, mpsc};
use tokio::task::JoinSet;

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

/// Verify if the process has administrative privileges or capabilities required for raw sockets
fn check_privileges() -> Result<()> {
    #[cfg(target_os = "macos")]
    {
        let euid = unsafe { libc::geteuid() };
        if euid != 0 {
            bail!(
                "Administrative privileges (root) are required to access /dev/bpf on macOS. Please run with sudo."
            );
        }
    }

    #[cfg(all(unix, not(target_os = "macos")))]
    {
        // On Linux, non-root users may have CAP_NET_RAW / CAP_NET_ADMIN capabilities set via setcap.
        // Datalink channel creation will attempt to open sockets and return actionable errors if unauthorized.
    }

    Ok(())
}

/// Create an Ethernet datalink channel with descriptive permission errors
fn create_datalink_channel(
    iface: &NetworkInterface,
) -> Result<(
    Box<dyn datalink::DataLinkSender>,
    Box<dyn datalink::DataLinkReceiver>,
)> {
    match datalink::channel(iface, Default::default()) {
        Ok(datalink::Channel::Ethernet(tx, rx)) => Ok((tx, rx)),
        Ok(_) => bail!(
            "Unsupported datalink channel type on interface '{}'",
            iface.name
        ),
        Err(e) => {
            #[cfg(target_os = "linux")]
            {
                bail!(
                    "Failed to create raw datalink channel on '{}': {}. Ensure you are running as root or have granted network capabilities: 'sudo setcap cap_net_raw,cap_net_admin+eip <binary>'",
                    iface.name,
                    e
                );
            }
            #[cfg(not(target_os = "linux"))]
            {
                bail!(
                    "Failed to create raw datalink channel on '{}': {}. Please run with elevated privileges (sudo).",
                    iface.name,
                    e
                );
            }
        }
    }
}

/// Calculate number of usable host addresses in an IPv4 network
fn calculate_host_count(net: ipnet::Ipv4Net) -> u64 {
    let prefix = net.prefix_len();
    if prefix >= 31 {
        0
    } else {
        (1u64 << (32 - prefix)) - 2
    }
}

/// Infer IPv4 subnet from the assigned interface addresses
fn infer_subnet(iface: &NetworkInterface) -> Result<ipnet::Ipv4Net> {
    for ip_net in &iface.ips {
        if let IpAddr::V4(ipv4) = ip_net.ip() {
            let prefix = ip_net.prefix();
            return ipnet::Ipv4Net::new(ipv4, prefix)
                .map(|net| net.trunc())
                .context("Failed to calculate IPv4 subnet from interface IP");
        }
    }
    bail!(
        "Interface '{}' does not have an assigned IPv4 address to infer subnet from. Please specify --target manually.",
        iface.name
    );
}

/// Asynchronously probe TCP ports concurrently with a bounded semaphore and per-port timeout
async fn scan_ports(
    ip: Ipv4Addr,
    ports: Vec<u16>,
    timeout: Duration,
    semaphore: Arc<Semaphore>,
) -> (Ipv4Addr, Vec<u16>) {
    let mut tasks = JoinSet::new();

    for port in ports {
        let sem = Arc::clone(&semaphore);
        tasks.spawn(async move {
            let Ok(_permit) = sem.acquire().await else {
                return None;
            };
            let addr = SocketAddr::V4(SocketAddrV4::new(ip, port));
            if matches!(
                tokio::time::timeout(timeout, TcpStream::connect(&addr)).await,
                Ok(Ok(_))
            ) {
                Some(port)
            } else {
                None
            }
        });
    }

    let mut open_ports = Vec::new();
    while let Some(res) = tasks.join_next().await {
        if let Ok(Some(port)) = res {
            open_ports.push(port);
        }
    }
    open_ports.sort_unstable();
    (ip, open_ports)
}

fn print_table_report(report: &ScanReport) {
    println!("\nInterface : {}", report.interface);
    println!("Subnet    : {}", report.target_network);
    println!("Discovered: {} active host(s)\n", report.total_found);

    if report.hosts.is_empty() {
        println!("No hosts responded to ARP requests.");
        return;
    }

    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL)
        .apply_modifier(UTF8_ROUND_CORNERS)
        .set_header(vec![
            Cell::new("IP Address").fg(Color::Cyan),
            Cell::new("MAC Address").fg(Color::Green),
            Cell::new("Vendor").fg(Color::Yellow),
            Cell::new("Open Ports").fg(Color::Magenta),
        ]);

    for host in &report.hosts {
        let ports_str = if host.open_ports.is_empty() {
            "-".to_string()
        } else {
            host.open_ports
                .iter()
                .map(|p| p.to_string())
                .collect::<Vec<_>>()
                .join(", ")
        };

        table.add_row(Row::from(vec![
            Cell::new(host.ip.to_string()),
            Cell::new(&host.mac),
            Cell::new(&host.vendor),
            Cell::new(ports_str),
        ]));
    }

    println!("{table}");
}

pub async fn run_scan(config: Cli) -> Result<()> {
    let interfaces = datalink::interfaces();

    // 1. Handle unprivileged --list-interfaces flag
    if config.list_interfaces {
        println!("Available Network Interfaces:\n");
        let mut table = Table::new();
        table
            .load_preset(UTF8_FULL)
            .apply_modifier(UTF8_ROUND_CORNERS)
            .set_header(vec![
                Cell::new("Interface").fg(Color::Cyan),
                Cell::new("MAC Address").fg(Color::Green),
                Cell::new("IPs").fg(Color::Yellow),
                Cell::new("Status").fg(Color::Magenta),
            ]);

        for iface in interfaces {
            let status = if iface.is_up() { "UP" } else { "DOWN" };
            let mac_str = iface
                .mac
                .map(|m| m.to_string())
                .unwrap_or_else(|| "None".to_string());
            let ips_str = iface
                .ips
                .iter()
                .map(|ip| ip.to_string())
                .collect::<Vec<_>>()
                .join(", ");

            table.add_row(Row::from(vec![
                Cell::new(&iface.name),
                Cell::new(mac_str),
                Cell::new(ips_str),
                Cell::new(status),
            ]));
        }

        println!("{table}");
        return Ok(());
    }

    // 2. Check for administrative privileges before raw socket usage
    check_privileges()?;

    // 3. Resolve the interface
    let target_interface: Option<NetworkInterface> = match config.interface {
        Some(ref name) => interfaces.into_iter().find(|iface| iface.name == *name),
        None => interfaces.into_iter().find(|iface| {
            iface.is_up() && !iface.is_loopback() && iface.ips.iter().any(|ip| ip.is_ipv4())
        }),
    };

    let iface = target_interface.context("Could not determine a valid network interface.")?;

    let mac = iface
        .mac
        .context(format!("Interface '{}' has no MAC address.", iface.name))?;

    // Extract source IPv4
    let source_ip = iface
        .ips
        .iter()
        .find_map(|ip| match ip.ip() {
            IpAddr::V4(ipv4) => Some(ipv4),
            _ => None,
        })
        .context(format!("Interface '{}' has no IPv4 address.", iface.name))?;

    // 4. Resolve target network (manual target or auto-inferred subnet)
    let target_network = match config.target {
        Some(ipnet::IpNet::V4(v4)) => v4,
        Some(ipnet::IpNet::V6(_)) => bail!("ARP scanning is only supported for IPv4 networks."),
        None => infer_subnet(&iface)?,
    };

    if target_network.prefix_len() < 16 && !config.allow_large_subnet {
        bail!(
            "Target network {} (/{}) contains more than 65,534 potential hosts. Scanning networks larger than /16 can cause severe network congestion. Pass --allow-large-subnet to proceed.",
            target_network,
            target_network.prefix_len()
        );
    }

    if !config.json {
        println!("Bound Interface : {} ({})", iface.name, mac);
        println!("Source IP       : {}", source_ip);
        println!("Target Network  : {}", target_network);
        if config.no_ports {
            println!("Port Scanning   : Disabled");
        } else {
            println!("Target Ports    : {:?}", &config.ports[..]);
        }
    }

    let (tx_results, mut rx_results) = mpsc::channel::<(Ipv4Addr, MacAddr)>(1000);
    let iface_clone = iface.clone();

    // 5. Spawn the synchronous listener in a blocking task
    let _listener_handle = tokio::task::spawn_blocking(move || -> Result<()> {
        let (_, mut rx) = create_datalink_channel(&iface_clone)?;

        loop {
            match rx.next() {
                Ok(frame) => {
                    if let Some(ethernet) = EthernetPacket::new(frame)
                        && ethernet.get_ethertype() == EtherTypes::Arp
                        && let Some(arp) = ArpPacket::new(ethernet.payload())
                        && arp.get_operation() == ArpOperations::Reply
                        && tx_results
                            .blocking_send((arp.get_sender_proto_addr(), arp.get_sender_hw_addr()))
                            .is_err()
                    {
                        break; // Channel closed, scanner completed
                    }
                }
                Err(e) => {
                    eprintln!("Error receiving packet: {}", e);
                    break;
                }
            }
        }
        Ok(())
    });

    // 6. Datalink TX channel
    let (mut tx, _) = create_datalink_channel(&iface)?;

    let host_count = calculate_host_count(target_network);

    if !config.json {
        println!("Broadcasting ARP requests to {host_count} hosts...");
    }

    let mut ethernet_buffer = [0u8; 42];
    let mut arp_buffer = [0u8; 28];

    for target_ip in target_network.hosts() {
        let mut ethernet_packet = MutableEthernetPacket::new(&mut ethernet_buffer).unwrap();
        ethernet_packet.set_destination(MacAddr::broadcast());
        ethernet_packet.set_source(mac);
        ethernet_packet.set_ethertype(EtherTypes::Arp);

        let mut arp_packet = MutableArpPacket::new(&mut arp_buffer).unwrap();
        arp_packet.set_hardware_type(ArpHardwareTypes::Ethernet);
        arp_packet.set_protocol_type(EtherTypes::Ipv4);
        arp_packet.set_hw_addr_len(6);
        arp_packet.set_proto_addr_len(4);
        arp_packet.set_operation(ArpOperations::Request);
        arp_packet.set_sender_hw_addr(mac);
        arp_packet.set_sender_proto_addr(source_ip);
        arp_packet.set_target_hw_addr(MacAddr::zero());
        arp_packet.set_target_proto_addr(target_ip);

        ethernet_packet.set_payload(arp_packet.packet());

        if let Some(res) = tx.send_to(ethernet_packet.packet(), None) {
            res.context("Failed to send ARP packet")?;
        }

        if config.arp_delay_us > 0 {
            tokio::time::sleep(Duration::from_micros(config.arp_delay_us)).await;
        }
    }

    // 7. Receive ARP replies and trigger concurrent port scanning
    let scan_timeout = tokio::time::sleep(Duration::from_secs(config.timeout));
    tokio::pin!(scan_timeout);

    let mut hosts_map: HashMap<Ipv4Addr, HostResult> = HashMap::new();
    let mut port_scan_tasks: JoinSet<(Ipv4Addr, Vec<u16>)> = JoinSet::new();
    let semaphore = Arc::new(Semaphore::new(config.concurrency));
    let port_timeout = Duration::from_millis(config.port_timeout_ms);
    let target_ports = config.ports.0.clone();

    loop {
        tokio::select! {
            Some((ip, mac_addr)) = rx_results.recv() => {
                if hosts_map.contains_key(&ip) {
                    continue;
                }

                if target_network.contains(&ip) {
                    let mac_bytes = [
                        mac_addr.0, mac_addr.1, mac_addr.2,
                        mac_addr.3, mac_addr.4, mac_addr.5
                    ];

                    let vendor_info = manuf::vendor(mac_bytes)
                        .map(|(short, long)| format!("{} ({})", short, long))
                        .unwrap_or_else(|| "Unknown Vendor".to_string());

                    let host = HostResult {
                        ip,
                        mac: mac_addr.to_string(),
                        vendor: vendor_info,
                        open_ports: Vec::new(),
                    };

                    hosts_map.insert(ip, host);

                    if !config.no_ports && !target_ports.is_empty() {
                        let sem = Arc::clone(&semaphore);
                        port_scan_tasks.spawn(scan_ports(ip, target_ports.clone(), port_timeout, sem));
                    }
                }
            }
            Some(res) = port_scan_tasks.join_next(), if !port_scan_tasks.is_empty() => {
                if let Ok((ip, ports)) = res
                    && let Some(host) = hosts_map.get_mut(&ip) {
                        host.open_ports = ports;
                    }
            }
            _ = &mut scan_timeout => {
                // Abort in-flight port scans immediately to uphold strict scan deadline
                port_scan_tasks.abort_all();
                while let Some(res) = port_scan_tasks.join_next().await {
                    if let Ok((ip, ports)) = res
                        && let Some(host) = hosts_map.get_mut(&ip) {
                            host.open_ports = ports;
                        }
                }
                break;
            }
        }
    }

    let mut hosts: Vec<HostResult> = hosts_map.into_values().collect();
    hosts.sort_by_key(|h| h.ip);

    let report = ScanReport {
        interface: iface.name,
        target_network: target_network.to_string(),
        total_found: hosts.len(),
        hosts,
    };

    if config.json {
        let json_str = serde_json::to_string_pretty(&report)?;
        println!("{json_str}");
    } else {
        print_table_report(&report);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn test_concurrent_scan_ports() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let open_port = listener.local_addr().unwrap().port();
        let closed_port = if open_port < 65535 {
            open_port + 1
        } else {
            open_port - 1
        };

        let semaphore = Arc::new(Semaphore::new(10));
        let timeout = Duration::from_millis(200);

        let (ip, ports) = scan_ports(
            Ipv4Addr::LOCALHOST,
            vec![open_port, closed_port],
            timeout,
            semaphore,
        )
        .await;

        assert_eq!(ip, Ipv4Addr::LOCALHOST);
        assert_eq!(ports, vec![open_port]);
    }

    #[test]
    fn test_calculate_host_count() {
        let net_24: ipnet::Ipv4Net = "192.168.1.0/24".parse().unwrap();
        assert_eq!(calculate_host_count(net_24), 254);

        let net_16: ipnet::Ipv4Net = "10.0.0.0/16".parse().unwrap();
        assert_eq!(calculate_host_count(net_16), 65534);

        let net_30: ipnet::Ipv4Net = "10.0.0.0/30".parse().unwrap();
        assert_eq!(calculate_host_count(net_30), 2);

        let net_31: ipnet::Ipv4Net = "10.0.0.0/31".parse().unwrap();
        assert_eq!(calculate_host_count(net_31), 0);

        let net_32: ipnet::Ipv4Net = "10.0.0.1/32".parse().unwrap();
        assert_eq!(calculate_host_count(net_32), 0);
    }
}
