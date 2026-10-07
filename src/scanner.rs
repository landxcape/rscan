use crate::cli::Cli;
use crate::core::arp::{broadcast_arp_requests, spawn_arp_listener};
use crate::core::network::{
    calculate_host_count, check_privileges, create_datalink_channel, infer_subnet,
};
use crate::core::port::scan_ports;
use crate::output::format::{
    print_interfaces_table, print_json_report, print_plain_report, print_table_report,
};
use crate::output::{HostResult, ScanReport};
use anyhow::{Context, Result, bail};
use pnet::datalink::{self, MacAddr, NetworkInterface};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{Semaphore, mpsc};
use tokio::task::JoinSet;

pub async fn run_scan(config: Cli) -> Result<()> {
    let interfaces = datalink::interfaces();

    // 1. Handle unprivileged --list-interfaces flag
    if config.list_interfaces {
        print_interfaces_table(&interfaces);
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

    if !config.json && !config.plain {
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

    // 5. Spawn the synchronous listener in a blocking task
    let (_, rx) = create_datalink_channel(&iface)?;
    let _listener_handle = spawn_arp_listener(rx, tx_results);

    // 6. Datalink TX channel
    let (mut tx, _) = create_datalink_channel(&iface)?;

    let host_count = calculate_host_count(target_network);
    if !config.json && !config.plain {
        println!("Broadcasting ARP requests to {host_count} hosts...");
    }

    broadcast_arp_requests(&mut tx, mac, source_ip, target_network, config.arp_delay_us).await?;

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

    if config.plain {
        print_plain_report(&report.hosts);
    } else if config.json {
        print_json_report(&report)?;
    } else {
        print_table_report(&report);
    }

    Ok(())
}
