use clap::Parser;
use ipnet::IpNet;
use std::collections::BTreeSet;
use std::ops::Deref;
use std::str::FromStr;

#[cfg_attr(not(test), allow(dead_code))]
pub const DEFAULT_PORTS: &[u16] = &[21, 22, 23, 80, 443, 445, 3389];

/// Parse comma-delimited ports and ranges (e.g., "22,80,443,8000-8080")
pub fn parse_ports(input: &str) -> Result<Vec<u16>, String> {
    if input.trim().is_empty() {
        return Err("Port specification cannot be empty".to_string());
    }

    let mut ports = BTreeSet::new();

    for token in input.split(',') {
        let token = token.trim();
        if token.is_empty() {
            continue;
        }

        if let Some((start_str, end_str)) = token.split_once('-') {
            let start = start_str
                .trim()
                .parse::<u16>()
                .map_err(|_| format!("Invalid start port in range: '{start_str}'"))?;
            let end = end_str
                .trim()
                .parse::<u16>()
                .map_err(|_| format!("Invalid end port in range: '{end_str}'"))?;

            if start == 0 || end == 0 {
                return Err("Port 0 is not a valid port number".to_string());
            }
            if start > end {
                return Err(format!(
                    "Invalid port range '{token}': start port {start} is greater than end port {end}"
                ));
            }

            for p in start..=end {
                ports.insert(p);
            }
        } else {
            let port = token
                .parse::<u16>()
                .map_err(|_| format!("Invalid port number: '{token}'"))?;
            if port == 0 {
                return Err("Port 0 is not a valid port number".to_string());
            }
            ports.insert(port);
        }
    }

    if ports.is_empty() {
        return Err("No valid ports specified".to_string());
    }

    Ok(ports.into_iter().collect())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortList(pub Vec<u16>);

impl Deref for PortList {
    type Target = [u16];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl FromStr for PortList {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        parse_ports(s).map(PortList)
    }
}

#[derive(Parser, Debug, Clone)]
#[command(
    name = "rscan",
    version,
    about = "High-performance Layer 2 ARP & TCP port network scanner",
    long_about = "A high-performance Layer 2 ARP network discovery and concurrent TCP port scanner.\n\
                  Broadcasts raw Ethernet frames to discover active hosts, resolves hardware manufacturers\n\
                  via IEEE OUI lookups, and probes open TCP ports with bounded async concurrency.",
    after_help = "EXAMPLES:\n  \
                    sudo rscan                               # Auto-detect local subnet and audit default ports\n  \
                    sudo rscan --no-ports                    # Fast host discovery using ARP only\n  \
                    sudo rscan -p 80,443,8000-8080           # Scan specific ports and port ranges\n  \
                    sudo rscan -t 10.0.0.0/24 -i eth0        # Specify target CIDR block and interface\n  \
                    sudo rscan -q | xargs -n1 ping -c 1      # Stream host IPs to Unix pipe\n  \
                    sudo rscan --json | jq .                 # Structured JSON output\n  \
                    rscan --list-interfaces                  # Inspect interfaces without root privileges\n\n\
                  LINUX CAPABILITIES:\n  \
                    Grant raw socket capability to run without sudo:\n  \
                    sudo setcap cap_net_raw,cap_net_admin+eip $(which rscan)"
)]
pub struct Cli {
    /// The target CIDR block to scan (e.g. 192.168.1.0/24). If omitted, inferred from the interface.
    #[arg(short, long, value_name = "CIDR", help_heading = "Network & Discovery")]
    pub target: Option<IpNet>,

    /// The network interface to bind to (e.g. en0, eth0)
    #[arg(
        short,
        long,
        value_name = "IFACE",
        help_heading = "Network & Discovery"
    )]
    pub interface: Option<String>,

    /// List all available network interfaces and exit (does not require sudo)
    #[arg(long, help_heading = "Network & Discovery")]
    pub list_interfaces: bool,

    /// Timeout in seconds to wait for ARP and port scan replies
    #[arg(
        short = 'w',
        long,
        default_value = "2",
        value_name = "SECS",
        help_heading = "Network & Discovery"
    )]
    pub timeout: u64,

    /// Delay in microseconds between consecutive ARP request transmissions
    #[arg(
        long,
        default_value = "0",
        value_name = "US",
        help_heading = "Network & Discovery"
    )]
    pub arp_delay_us: u64,

    /// Allow scanning subnets larger than /16 (> 65,534 potential hosts)
    #[arg(long, help_heading = "Network & Discovery")]
    pub allow_large_subnet: bool,

    /// Custom ports or ranges to scan (e.g., "22,80,443,8000-8080")
    #[arg(
        short,
        long,
        default_value = "21,22,23,80,443,445,3389",
        value_name = "PORTS",
        help_heading = "Port Scanning"
    )]
    pub ports: PortList,

    /// Disable TCP port scanning entirely
    #[arg(long, help_heading = "Port Scanning")]
    pub no_ports: bool,

    /// Maximum concurrent TCP connection attempts across all hosts
    #[arg(
        short = 'c',
        long,
        default_value = "100",
        value_name = "NUM",
        help_heading = "Port Scanning"
    )]
    pub concurrency: usize,

    /// Timeout in milliseconds for each TCP port connection attempt
    #[arg(
        long,
        default_value = "300",
        value_name = "MS",
        help_heading = "Port Scanning"
    )]
    pub port_timeout_ms: u64,

    /// Output results in JSON format
    #[arg(long, help_heading = "Output Formatting")]
    pub json: bool,

    /// Output only discovered host IP addresses (one per line), ideal for piping
    #[arg(
        short = 'q',
        long,
        aliases = ["quiet"],
        help_heading = "Output Formatting"
    )]
    pub plain: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ports_single_and_comma() {
        assert_eq!(parse_ports("80").unwrap(), vec![80]);
        assert_eq!(parse_ports("80,443").unwrap(), vec![80, 443]);
        assert_eq!(parse_ports(" 80 , 443 ").unwrap(), vec![80, 443]);
    }

    #[test]
    fn test_parse_ports_range() {
        assert_eq!(
            parse_ports("8000-8003").unwrap(),
            vec![8000, 8001, 8002, 8003]
        );
    }

    #[test]
    fn test_parse_ports_mixed_and_dedup() {
        assert_eq!(
            parse_ports("22,80-82,443,22").unwrap(),
            vec![22, 80, 81, 82, 443]
        );
    }

    #[test]
    fn test_parse_ports_errors() {
        assert!(parse_ports("").is_err());
        assert!(parse_ports("abc").is_err());
        assert!(parse_ports("0").is_err());
        assert!(parse_ports("8000-7000").is_err());
        assert!(parse_ports("0-80").is_err());
    }

    #[test]
    fn test_cli_default_parsing() {
        let args = Cli::parse_from(["rscan"]);
        assert_eq!(args.timeout, 2);
        assert_eq!(args.port_timeout_ms, 300);
        assert_eq!(args.concurrency, 100);
        assert_eq!(args.arp_delay_us, 0);
        assert!(!args.allow_large_subnet);
        assert_eq!(&args.ports[..], DEFAULT_PORTS);
        assert!(!args.no_ports);
        assert!(!args.json);
        assert!(!args.plain);
        assert!(!args.list_interfaces);
        assert!(args.target.is_none());
        assert!(args.interface.is_none());
    }

    #[test]
    fn test_cli_custom_ports_and_flags() {
        let args = Cli::parse_from([
            "rscan",
            "-p",
            "80,443,8000-8002",
            "--port-timeout-ms",
            "150",
            "-c",
            "50",
            "--arp-delay-us",
            "250",
            "--allow-large-subnet",
            "--no-ports",
            "--json",
            "-q",
            "-w",
            "5",
        ]);
        assert_eq!(&args.ports[..], &[80, 443, 8000, 8001, 8002]);
        assert_eq!(args.port_timeout_ms, 150);
        assert_eq!(args.concurrency, 50);
        assert_eq!(args.arp_delay_us, 250);
        assert!(args.allow_large_subnet);
        assert!(args.no_ports);
        assert!(args.json);
        assert!(args.plain);
        assert_eq!(args.timeout, 5);
    }
}
