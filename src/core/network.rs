use anyhow::{Context, Result, bail};
#[cfg(not(target_os = "windows"))]
use pnet::datalink;
use pnet::datalink::NetworkInterface;
use std::net::IpAddr;

/// Verify if the process has administrative privileges or capabilities required for raw sockets
pub fn check_privileges() -> Result<()> {
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
#[cfg(not(target_os = "windows"))]
pub fn create_datalink_channel(
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

/// Infer IPv4 subnet from the assigned interface addresses
pub fn infer_subnet(iface: &NetworkInterface) -> Result<ipnet::Ipv4Net> {
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

/// Calculate number of usable host addresses in an IPv4 network
pub fn calculate_host_count(net: ipnet::Ipv4Net) -> u64 {
    let prefix = net.prefix_len();
    if prefix >= 31 {
        0
    } else {
        (1u64 << (32 - prefix)) - 2
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
