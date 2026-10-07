use anyhow::{Context, Result};
use pnet::datalink::{DataLinkReceiver, DataLinkSender, MacAddr};
use pnet::packet::Packet;
use pnet::packet::arp::{ArpHardwareTypes, ArpOperations, ArpPacket, MutableArpPacket};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
use std::net::Ipv4Addr;
use std::time::Duration;
use tokio::sync::mpsc::Sender;
use tokio::task::JoinHandle;

/// Broadcast ARP requests to every host in the target subnet
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

/// Spawns a blocking listener on the datalink channel capturing ARP replies
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
