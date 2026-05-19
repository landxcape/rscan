use clap::Parser;
use ipnet::IpNet;

#[derive(Parser, Debug)]
#[command(name = "rscan", about = "Definitive Layer 2 ARP Scanner")]
pub struct Cli {
    /// The target CIDR block to scan
    #[arg(short, long)]
    pub target: Option<IpNet>,

    /// The network interface to bind to
    #[arg(short, long)]
    pub interface: Option<String>,

    /// List all available network interfaces and exit
    #[arg(long)]
    pub list_interfaces: bool,
}
