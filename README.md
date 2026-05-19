# rscan

A Layer 2 ARP scanner and TCP port auditing tool.

`rscan` identifies active hosts on a local network by broadcasting ARP requests and identifies running services via parallel TCP port probing. It includes MAC vendor identification via an embedded OUI database.

## Features

- **Host Discovery:** ARP-based scanning for IPv4 CIDR blocks.
- **Port Auditing:** Parallel TCP connect probes for common ports (SSH, HTTP, SMB, etc.).
- **Vendor Lookup:** MAC OUI matching for hardware manufacturer identification.
- **Interface Selection:** Auto-discovery of the primary network interface or manual selection.
- **Async Runtime:** Built with `tokio` for concurrent scanning.

## Installation

### Prerequisites

- Rust toolchain (stable)
- Root/administrative privileges (required for raw socket access)

### Build

```bash
git clone https://github.com/landxcape/rscan.git
cd rscan
cargo build --release
```

The binary is located at `./target/release/rscan`.

## Usage

### Scan Subnet
Scan a subnet using the default interface:
```bash
sudo ./target/release/rscan --target 192.168.1.0/24
```

### Specify Interface
```bash
sudo ./target/release/rscan --target 192.168.1.0/24 --interface eth0
```

### List Interfaces
```bash
./target/release/rscan --list-interfaces
```

## Architecture

- **Packet Handling:** Uses `pnet` for raw Ethernet and ARP frame management.
- **Concurrency:** Uses `tokio::task::spawn_blocking` to bridge synchronous packet capture with the asynchronous runtime.
- **Error Handling:** Uses `anyhow` for context-aware error propagation.
- **Data:** Uses `manuf` for the MAC OUI database.

## License

MIT
