use crate::output::report::{HostResult, ScanReport};
use anyhow::Result;
use comfy_table::modifiers::UTF8_ROUND_CORNERS;
use comfy_table::presets::UTF8_FULL;
use comfy_table::{Cell, Color, Row, Table};
use pnet::datalink::NetworkInterface;

pub fn print_interfaces_table(interfaces: &[NetworkInterface]) {
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
}

pub fn print_table_report(report: &ScanReport) {
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

pub fn print_json_report(report: &ScanReport) -> Result<()> {
    let json_str = serde_json::to_string_pretty(report)?;
    println!("{json_str}");
    Ok(())
}

pub fn print_plain_report(hosts: &[HostResult]) {
    for host in hosts {
        println!("{}", host.ip);
    }
}
