use clap::Parser;
use ipnet::IpNet;

pub const DEFAULT_PORTS: &[u16] = &[21, 22, 23, 80, 443, 445, 3389];

#[derive(Parser, Debug, Clone)]
#[command(
    name = "rscan",
    version,
    about = "High-performance Layer 2 ARP & Port Scanner"
)]
pub struct Cli {
    /// The target CIDR block to scan (e.g. 192.168.1.0/24). If omitted, inferred from the interface.
    #[arg(short, long)]
    pub target: Option<IpNet>,

    /// The network interface to bind to (e.g. en0, eth0)
    #[arg(short, long)]
    pub interface: Option<String>,

    /// List all available network interfaces and exit (does not require sudo)
    #[arg(long)]
    pub list_interfaces: bool,

    /// Timeout in seconds to wait for ARP and port scan replies
    #[arg(short = 'w', long, default_value = "2")]
    pub timeout: u64,

    /// Custom ports to scan (e.g., "22,80,443,8080")
    #[arg(short, long, value_delimiter = ',', default_values_t = [21, 22, 23, 80, 443, 445, 3389])]
    pub ports: Vec<u16>,

    /// Disable TCP port scanning entirely
    #[arg(long)]
    pub no_ports: bool,

    /// Output results in JSON format
    #[arg(long)]
    pub json: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cli_default_parsing() {
        let args = Cli::parse_from(["rscan"]);
        assert_eq!(args.timeout, 2);
        assert_eq!(args.ports, DEFAULT_PORTS);
        assert!(!args.no_ports);
        assert!(!args.json);
        assert!(!args.list_interfaces);
        assert!(args.target.is_none());
        assert!(args.interface.is_none());
    }

    #[test]
    fn test_cli_custom_ports_and_flags() {
        let args = Cli::parse_from([
            "rscan",
            "-p",
            "80,443,8080",
            "--no-ports",
            "--json",
            "-w",
            "5",
        ]);
        assert_eq!(args.ports, vec![80, 443, 8080]);
        assert!(args.no_ports);
        assert!(args.json);
        assert_eq!(args.timeout, 5);
    }
}
