use anyhow::Result;
use pnet::datalink::MacAddr;
use std::net::Ipv4Addr;
use tokio::sync::mpsc::Sender;

#[cfg(not(target_os = "windows"))]
use anyhow::Context;
#[cfg(not(target_os = "windows"))]
use pnet::datalink::{DataLinkReceiver, DataLinkSender};
#[cfg(not(target_os = "windows"))]
use pnet::packet::Packet;
#[cfg(not(target_os = "windows"))]
use pnet::packet::arp::{ArpHardwareTypes, ArpOperations, ArpPacket, MutableArpPacket};
#[cfg(not(target_os = "windows"))]
use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
#[cfg(not(target_os = "windows"))]
use std::time::Duration;
#[cfg(not(target_os = "windows"))]
use tokio::task::JoinHandle;

/// Broadcast ARP requests to every host in the target subnet (Unix/macOS/Linux via raw Ethernet frames)
#[cfg(not(target_os = "windows"))]
pub async fn broadcast_arp_requests(
    tx: &mut Box<dyn DataLinkSender>,
    source_mac: MacAddr,
    source_ip: Ipv4Addr,
    target_network: ipnet::Ipv4Net,
    delay_us: u64,
) -> Result<()> {
    let mut ethernet_buffer = [0u8; 42];
    let mut arp_buffer = [0u8; 28];

    for target_ip in target_network.hosts() {
        let mut ethernet_packet = MutableEthernetPacket::new(&mut ethernet_buffer).unwrap();
        ethernet_packet.set_destination(MacAddr::broadcast());
        ethernet_packet.set_source(source_mac);
        ethernet_packet.set_ethertype(EtherTypes::Arp);

        let mut arp_packet = MutableArpPacket::new(&mut arp_buffer).unwrap();
        arp_packet.set_hardware_type(ArpHardwareTypes::Ethernet);
        arp_packet.set_protocol_type(EtherTypes::Ipv4);
        arp_packet.set_hw_addr_len(6);
        arp_packet.set_proto_addr_len(4);
        arp_packet.set_operation(ArpOperations::Request);
        arp_packet.set_sender_hw_addr(source_mac);
        arp_packet.set_sender_proto_addr(source_ip);
        arp_packet.set_target_hw_addr(MacAddr::zero());
        arp_packet.set_target_proto_addr(target_ip);

        ethernet_packet.set_payload(arp_packet.packet());

        if let Some(res) = tx.send_to(ethernet_packet.packet(), None) {
            res.context("Failed to send ARP packet")?;
        }

        if delay_us > 0 {
            tokio::time::sleep(Duration::from_micros(delay_us)).await;
        }
    }

    Ok(())
}

/// Spawns a blocking listener on the datalink channel capturing ARP replies (Unix/macOS/Linux)
#[cfg(not(target_os = "windows"))]
pub fn spawn_arp_listener(
    mut rx: Box<dyn DataLinkReceiver>,
    tx_results: Sender<(Ipv4Addr, MacAddr)>,
) -> JoinHandle<Result<()>> {
    tokio::task::spawn_blocking(move || -> Result<()> {
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
                        break;
                    }
                }
                Err(e) => {
                    eprintln!("Error receiving packet: {}", e);
                    break;
                }
            }
        }
        Ok(())
    })
}

// ============================================================================
// Windows Native ARP implementation (via iphlpapi.dll SendARP, zero drivers needed)
// ============================================================================

#[cfg(target_os = "windows")]
#[link(name = "iphlpapi")]
unsafe extern "system" {
    fn SendARP(dest_ip: u32, src_ip: u32, mac_addr: *mut u8, phy_addr_len: *mut u32) -> u32;
}

#[cfg(target_os = "windows")]
fn send_arp_probe(ip: Ipv4Addr) -> Option<MacAddr> {
    // Windows SendARP expects IPAddr in network byte order packed in u32
    let dest_ip = u32::from_ne_bytes(ip.octets());
    let mut mac_buf = [0u8; 6];
    let mut mac_len = 6u32;

    let res = unsafe { SendARP(dest_ip, 0, mac_buf.as_mut_ptr(), &mut mac_len as *mut u32) };

    if res == 0 && mac_len == 6 {
        Some(MacAddr::new(
            mac_buf[0], mac_buf[1], mac_buf[2], mac_buf[3], mac_buf[4], mac_buf[5],
        ))
    } else {
        None
    }
}

/// Concurrently resolves ARP entries for an entire subnet on Windows using native OS SendARP
#[cfg(target_os = "windows")]
pub async fn scan_windows_subnet(
    target_network: ipnet::Ipv4Net,
    tx_results: Sender<(Ipv4Addr, MacAddr)>,
    concurrency: usize,
) -> Result<()> {
    use std::sync::Arc;
    use tokio::sync::Semaphore;
    use tokio::task::JoinSet;

    let semaphore = Arc::new(Semaphore::new(concurrency));
    let mut tasks = JoinSet::new();

    for ip in target_network.hosts() {
        let sem = Arc::clone(&semaphore);
        let tx = tx_results.clone();

        tasks.spawn(async move {
            let _permit = match sem.acquire().await {
                Ok(p) => p,
                Err(_) => return,
            };

            // SendARP is a blocking synchronous system call; run on blocking worker pool
            let result = tokio::task::spawn_blocking(move || send_arp_probe(ip)).await;
            if let Ok(Some(mac)) = result {
                let _ = tx.send((ip, mac)).await;
            }
        });
    }

    while tasks.join_next().await.is_some() {}

    Ok(())
}
