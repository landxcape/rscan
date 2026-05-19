use crate::cli::Cli;
use anyhow::{Context, Result, bail};
use pnet::datalink::{self, MacAddr, NetworkInterface};
use pnet::packet::Packet;
use pnet::packet::arp::{ArpHardwareTypes, ArpOperations, ArpPacket, MutableArpPacket};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::task::JoinSet;

const COMMON_PORTS: &[u16] = &[21, 22, 23, 80, 443, 445, 3389];

/// Verify if the process has administrative privileges (required for raw sockets)
fn check_privileges() -> Result<()> {
    #[cfg(unix)]
    {
        let uid = unsafe { libc::getuid() };
        if uid != 0 {
            bail!("Administrative privileges required. Please run with sudo.");
        }
    }
    // TODO: Add Windows privilege check if needed
    Ok(())
}

async fn scan_ports(ip: Ipv4Addr) -> (Ipv4Addr, Vec<u16>) {
    let mut open_ports = Vec::new();
    for &port in COMMON_PORTS {
        let addr = std::net::SocketAddr::V4(std::net::SocketAddrV4::new(ip, port));
        if tokio::time::timeout(Duration::from_millis(500), TcpStream::connect(&addr))
            .await
            .is_ok()
        {
            open_ports.push(port);
        }
    }
    (ip, open_ports)
}

pub async fn run_scan(config: Cli) -> Result<()> {
    // 1. Check for root privileges early
    check_privileges()?;

    let interfaces = datalink::interfaces();

    // 2. Handle the explicit list command
    if config.list_interfaces {
        println!("Available Network Interfaces:");
        for iface in interfaces {
            println!("* {}: MAC {:?}, IPs {:?}", iface.name, iface.mac, iface.ips);
        }
        return Ok(());
    }

    // 3. Enforce the target requirement if we are actually scanning
    let target_cidr = config
        .target
        .context("A target CIDR block is required for scanning (e.g., --target 192.168.1.0/24)")?;

    // 4. Resolve the interface strictly
    let target_interface: Option<NetworkInterface> = match config.interface {
        Some(ref name) => interfaces.into_iter().find(|iface| iface.name == *name),
        None => {
            println!("No interface specified. Attempting auto-discovery...");
            interfaces.into_iter().find(|iface| {
                iface.is_up() && !iface.is_loopback() && iface.ips.iter().any(|ip| ip.is_ipv4())
            })
        }
    };

    // 5. Verify the hardware binding
    let iface = target_interface.context("Could not determine a valid network interface.")?;

    let mac = iface
        .mac
        .context(format!("Interface {} has no MAC address.", iface.name))?;

    // Extract source IPv4
    let source_ip = iface
        .ips
        .iter()
        .find_map(|ip| match ip.ip() {
            IpAddr::V4(ipv4) => Some(ipv4),
            _ => None,
        })
        .context(format!("Interface {} has no IPv4 address.", iface.name))?;

    // Extract target IPv4 network
    let target_network = match target_cidr {
        ipnet::IpNet::V4(v4) => v4,
        _ => bail!("ARP scanning is only supported for IPv4 networks."),
    };

    println!("Successfully bound to interface: {}", iface.name);
    println!("Hardware MAC Address: {}", mac);
    println!("Source IP: {}", source_ip);
    println!("Target Network: {}", target_network);

    let (tx_results, mut rx_results) = mpsc::channel::<(Ipv4Addr, MacAddr)>(1000);
    let iface_clone = iface.clone();

    // Spawn the synchronous listener in a blocking task
    let _listener_handle = tokio::task::spawn_blocking(move || -> Result<()> {
        let (_, mut rx) = match datalink::channel(&iface_clone, Default::default()) {
            Ok(datalink::Channel::Ethernet(tx, rx)) => (tx, rx),
            Ok(_) => bail!("Unhandled channel type"),
            Err(e) => bail!("Failed to create datalink channel: {}", e),
        };

        loop {
            match rx.next() {
                Ok(frame) => {
                    if let Some(ethernet) = EthernetPacket::new(frame) {
                        if ethernet.get_ethertype() == EtherTypes::Arp {
                            if let Some(arp) = ArpPacket::new(ethernet.payload()) {
                                if arp.get_operation() == ArpOperations::Reply {
                                    // Send discovered host back to async context
                                    if tx_results
                                        .blocking_send((
                                            arp.get_sender_proto_addr(),
                                            arp.get_sender_hw_addr(),
                                        ))
                                        .is_err()
                                    {
                                        break; // Receiver dropped, stop listening
                                    }
                                }
                            }
                        }
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

    let (mut tx, _) = match datalink::channel(&iface, Default::default()) {
        Ok(datalink::Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => bail!("Unhandled channel type"),
        Err(e) => bail!("Failed to create datalink tx channel: {}", e),
    };

    let target_hosts: Vec<Ipv4Addr> = target_cidr
        .hosts()
        .filter_map(|ip| match ip {
            IpAddr::V4(v4) => Some(v4),
            _ => None,
        })
        .collect();

    println!("Scanning {} hosts...", target_hosts.len());

    let mut ethernet_buffer = [0u8; 42];
    let mut arp_buffer = [0u8; 28];

    for target_ip in target_hosts {
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
    }

    let timeout = tokio::time::sleep(Duration::from_secs(2));
    tokio::pin!(timeout);

    let mut found_count = 0;
    let mut port_scan_tasks: JoinSet<(Ipv4Addr, Vec<u16>)> = JoinSet::new();
    let mut discovered_ips = std::collections::HashSet::new();

    loop {
        tokio::select! {
            Some((ip, mac_addr)) = rx_results.recv() => {
                // 1. De-duplicate based on IP
                if discovered_ips.contains(&ip) {
                    continue;
                }

                // 2. Ensure the reply is from the target network
                if target_cidr.contains(&IpAddr::V4(ip)) {
                    discovered_ips.insert(ip);
                    port_scan_tasks.spawn(scan_ports(ip));

                    // 3. Vendor Lookup
                    // pnet MacAddr is (u8, u8, u8, u8, u8, u8)
                    let mac_bytes = [
                        mac_addr.0, mac_addr.1, mac_addr.2,
                        mac_addr.3, mac_addr.4, mac_addr.5
                    ];

                    let vendor_info = manuf::vendor(mac_bytes)
                        .map(|(short, long)| format!("{} - {}", short, long))
                        .unwrap_or_else(|| "Unknown Vendor".to_string());

                    println!(
                        "Host Found! IP: {:<15} MAC: {} [{}]",
                        ip, mac_addr, vendor_info
                    );
                    found_count += 1;
                }
            }
            Some(res) = port_scan_tasks.join_next(), if !port_scan_tasks.is_empty() => {
                if let Ok((ip, ports)) = res {
                    if !ports.is_empty() {
                        println!("  - IP: {:<15} Open Ports: {:?}", ip, ports);
                    }
                }
            }
            _ = &mut timeout => {
                println!("\nScan complete. Found {} unique hosts.", found_count);
                // Wait for any remaining port scan tasks
                while let Some(res) = port_scan_tasks.join_next().await {
                    if let Ok((ip, ports)) = res {
                        if !ports.is_empty() {
                            println!("  - IP: {:<15} Open Ports: {:?}", ip, ports);
                        }
                    }
                }
                break;
            }
        }
    }

    Ok(())
}
