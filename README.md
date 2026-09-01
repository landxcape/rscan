# rscan

A high-performance Layer 2 ARP scanner and TCP port discovery tool written in Rust.

`rscan` identifies active IPv4 hosts on a local subnet by broadcasting raw ARP requests, resolves hardware manufacturers via an embedded MAC OUI database, and concurrently audits open TCP ports.

## Features

- **Automatic Subnet Discovery:** Automatically derives the local IPv4 subnet CIDR from active interfaces if `--target` is omitted.
- **Fast ARP Broadcasting & Sniffing:** Uses `pnet` to generate raw Ethernet frames and sniff ARP replies asynchronously.
- **Concurrent TCP Port Auditing:** Parallel TCP probing with customizable port lists (`-p, --ports`) or instant ARP-only scanning (`--no-ports`).
- **Hardware Vendor Lookup:** Offline MAC OUI matching for hardware manufacturer identification (`manuf`).
- **Rich Terminal Table & JSON Output:** Beautiful UTF-8 table rendering with `comfy-table` and structured JSON reporting (`--json`).
- **Unprivileged Interface Listing:** Inspect local network interfaces and status without requiring `sudo`.

## Installation

### From Source

```bash
cargo install --path .
```

### Manual Build

```bash
git clone https://github.com/landxcape/rscan.git
cd rscan
cargo build --release
```

The compiled binary will be located at `./target/release/rscan`.

## Usage

*Note: Raw socket operations require root / administrator privileges (`sudo`). Interface listing does not require `sudo`.*

### Auto-Detect Subnet and Scan

```bash
sudo rscan
```

### Scan Specific Subnet & Interface

```bash
sudo rscan --target 192.168.1.0/24 --interface en0
```

### Fast Scan (Skip Port Auditing)

```bash
sudo rscan --no-ports
```

### Custom Port List & Timeout

```bash
sudo rscan -p 22,80,443,8080,3000 -w 3
```

### JSON Output (Scripting & Automation)

```bash
sudo rscan --json | jq .
```

### List Available Network Interfaces

```bash
rscan --list-interfaces
```

## CLI Reference

```
Usage: rscan [OPTIONS]

Options:
  -t, --target <TARGET>        The target CIDR block to scan (e.g. 192.168.1.0/24). If omitted, inferred from the interface
  -i, --interface <INTERFACE>  The network interface to bind to (e.g. en0, eth0)
      --list-interfaces        List all available network interfaces and exit (does not require sudo)
  -w, --timeout <TIMEOUT>      Timeout in seconds to wait for ARP and port scan replies [default: 2]
  -p, --ports <PORTS>          Custom ports to scan (e.g., "22,80,443,8080") [default: 21 22 23 80 443 445 3389]
      --no-ports               Disable TCP port scanning entirely
      --json                   Output results in JSON format
  -h, --help                   Print help
  -V, --version                Print version
```

## License

MIT
