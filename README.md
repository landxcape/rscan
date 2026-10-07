# rscan

[![Rust](https://img.shields.io/badge/Rust-2024%20Edition-orange?logo=rust)](https://www.rust-lang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Async: Tokio](https://img.shields.io/badge/Async-Tokio-brightgreen?logo=tokio)](https://tokio.rs/)
[![Platform](https://img.shields.io/badge/Platform-macOS%20%7C%20Linux%20%7C%20Windows-lightgrey)]()

A high-performance Layer 2 ARP network discovery and concurrent TCP port scanner written in Rust.

`rscan` sweeps local subnets by broadcasting raw Ethernet frames (on macOS/Linux) or utilizing native OS IP Helper APIs (on Windows), sniffs ARP replies to bypass host-level firewalls that block ICMP echo requests, resolves hardware manufacturers against an offline IEEE OUI database, and concurrently audits open TCP ports using bounded asynchronous tasks.

---

## Features

- **Layer 2 ARP Discovery:** Bypasses host firewalls that silence ICMP ping probes by broadcasting raw ARP frames directly via `pnet` (macOS/Linux) or native Win32 `SendARP` (Windows).
- **Zero Drivers on Windows:** Windows discovery runs as a self-contained single executable with zero external drivers (no Npcap/WinPcap required) and without requiring administrator privileges.
- **Automatic Subnet & Interface Resolution:** Inactive or unconfigured flags default to deriving the local active IPv4 subnet and hardware interface automatically.
- **Flexible Port Syntax:** Supports single ports, comma-separated lists, and continuous port ranges (e.g., `-p 22,80,443,8000-8080`) with automatic deduplication.
- **Bounded Async TCP Probing:** Utilizes Tokio and `tokio::sync::Semaphore` to probe ports across discovered hosts with strict file-descriptor limits and configurable timeouts.
- **Subnet Safety Guardrails & Pacing:** Safeguards against accidental network saturation on wide subnets (< `/16`) and offers microsecond frame pacing (`--arp-delay-us`).
- **Hardware Vendor Identification:** Resolves MAC addresses to manufacturers via the IEEE OUI database (`manuf`).
- **Flexible Output Formats:**
  - Formatted UTF-8 ASCII tables via `comfy-table`.
  - Structured JSON with `--json` for machine ingestion.
  - Line-by-line IP stream with `--plain` / `-q` for Unix pipelines.
- **Platform Capability Awareness:** Detects root requirements on macOS (`/dev/bpf`), supports non-root execution on Linux via `cap_net_raw`, and runs out-of-the-box on Windows.

---

## Installation

### Option 1: Homebrew (macOS & Linux - Recommended)

Install pre-compiled release binaries via the official `landxcape` tap:

```bash
brew tap landxcape/tap
brew install landxcape/tap/rscan
```

To update `rscan` later:
```bash
brew update && brew upgrade rscan
```

### Option 2: Pre-Compiled Standalone Binaries (macOS, Linux, Windows)

Download the latest pre-compiled archive for your architecture from the [GitHub Releases](https://github.com/landxcape/rscan/releases):

| Platform | Architecture | Archive |
| :--- | :--- | :--- |
| **macOS** | Apple Silicon (`arm64`) | `rscan-macos-aarch64.tar.gz` |
| **macOS** | Intel (`x86_64`) | `rscan-macos-x86_64.tar.gz` |
| **Linux** | `x86_64` | `rscan-linux-x86_64.tar.gz` |
| **Windows** | `x86_64` | `rscan-windows-x86_64.zip` |

Extract and place the binary (`rscan` or `rscan.exe`) anywhere in your `PATH` (e.g. `/usr/local/bin` on Unix).

### Option 3: From Source (Rust Toolchain)

```bash
git clone https://github.com/landxcape/rscan.git
cd rscan
cargo install --path .
```

### Linux Non-Root Execution (`setcap`)
To run `rscan` on Linux without prefixing `sudo`, grant raw socket capabilities:

```bash
sudo setcap cap_net_raw,cap_net_admin+eip $(which rscan)
```

---

## Usage & Recipes

### 1. Automatic Local Subnet Audit
Derives the default network interface and active IPv4 subnet, broadcast-probes ARP, and scans common TCP ports (`21, 22, 23, 80, 443, 445, 3389`):

```bash
sudo rscan
```

### 2. Fast Host Discovery (ARP Only)
Bypasses TCP port scanning to return active hosts instantaneously:

```bash
sudo rscan --no-ports
```

### 3. Web & Application Service Sweep
Probes web and development ports with ranges:

```bash
sudo rscan -p 80,443,3000,5000,8000-8080
```

### 4. Custom Subnet & Interface
Target an explicit CIDR block over a selected interface:

```bash
sudo rscan --target 10.0.0.0/24 --interface eth0
```

### 5. High-Throughput / Aggressive Scan
Increases concurrent TCP probes to 250 connections with a fast 150ms per-port timeout:

```bash
sudo rscan -p 1-1024 -c 250 --port-timeout-ms 150 -w 3
```

### 6. Large Subnet Sweep with Packet Pacing
Scans larger subnets safely by inserting microsecond delays between consecutive ARP broadcasts:

```bash
sudo rscan --target 172.16.0.0/16 --allow-large-subnet --arp-delay-us 100
```

### 7. Unix Shell Pipelines (`--plain` / `-q`)
Stream raw host IPs (one per line) for integration with external CLI tools:

```bash
# Ping sweep discovered hosts
sudo rscan -q | xargs -n1 ping -c 1

# Run deep Nmap service version detection on active hosts
sudo rscan -q --target 192.168.1.0/24 | xargs -r nmap -sV -p 80,443
```

### 8. JSON Ingestion
Output machine-readable JSON for logging or security automation:

```bash
sudo rscan --json | jq '.hosts[] | {ip: .ip, vendor: .vendor, ports: .open_ports}'
```

### 9. Interface Inspection (No Privileges Required)
List network interfaces and current status without `sudo`:

```bash
rscan --list-interfaces
```

---

## Output Examples

### Terminal Table Output
```text
Bound Interface : en0 (a4:83:e7:21:bb:12)
Source IP       : 192.168.1.150
Target Network  : 192.168.1.0/24
Target Ports    : [22, 80, 443, 8080]
Broadcasting ARP requests to 254 hosts...

Interface : en0
Subnet    : 192.168.1.0/24
Discovered: 3 active host(s)

┌───────────────┬───────────────────┬─────────────────────────────────┬────────────┐
│ IP Address    │ MAC Address       │ Vendor                          │ Open Ports │
├───────────────┼───────────────────┼─────────────────────────────────┼────────────┤
│ 192.168.1.1   │ 74:83:c2:1a:2b:3c │ Ubiquiti Networks Inc.          │ 22, 80, 443│
├───────────────┼───────────────────┼─────────────────────────────────┼────────────┤
│ 192.168.1.100 │ b8:27:eb:d4:5e:6f │ Raspberry Pi Foundation         │ 22         │
├───────────────┼───────────────────┼─────────────────────────────────┼────────────┤
│ 192.168.1.120 │ 00:11:32:98:76:54 │ Synology Incorporated           │ 80, 5000   │
└───────────────┴───────────────────┴─────────────────────────────────┴────────────┘
```

### Structured JSON Output
```json
{
  "interface": "en0",
  "target_network": "192.168.1.0/24",
  "total_found": 1,
  "hosts": [
    {
      "ip": "192.168.1.1",
      "mac": "74:83:c2:1a:2b:3c",
      "vendor": "Ubiquiti Networks Inc.",
      "open_ports": [22, 80, 443]
    }
  ]
}
```

---

## CLI Reference

```text
Usage: rscan [OPTIONS]

Options:
  -h, --help     Print help (see more with '--help')
  -V, --version  Print version

Network & Discovery:
  -t, --target <CIDR>       The target CIDR block to scan (e.g. 192.168.1.0/24)
  -i, --interface <IFACE>   The network interface to bind to (e.g. en0, eth0)
      --list-interfaces     List all available network interfaces and exit
  -w, --timeout <SECS>      Timeout in seconds to wait for replies [default: 2]
      --arp-delay-us <US>   Delay in microseconds between ARP packets [default: 0]
      --allow-large-subnet  Allow scanning subnets larger than /16

Port Scanning:
  -p, --ports <PORTS>         Ports or ranges to scan (e.g. "22,80,443,8000-8080")
                              [default: 21,22,23,80,443,445,3389]
      --no-ports              Disable TCP port scanning entirely
  -c, --concurrency <NUM>     Maximum concurrent TCP connection attempts [default: 100]
      --port-timeout-ms <MS>  Timeout in milliseconds per TCP attempt [default: 300]

Output Formatting:
      --json   Output results in JSON format
  -q, --plain  Output only discovered host IP addresses (one per line)
```

---

## Architecture

`rscan` is designed with modular separation between network packet crafting, async I/O, and reporting:

```text
rscan/src/
├── main.rs          # Application entrypoint
├── cli.rs           # Clap specification & port range parsing
├── scanner.rs       # Scan orchestration engine
├── core/
│   ├── arp.rs       # Raw ARP packet builder, broadcasting & listener
│   ├── network.rs   # Interface resolution, subnet math, privilege validation
│   └── port.rs      # Semaphore-bounded concurrent TCP port scanner
└── output/
    ├── format.rs    # Terminal tables, JSON serialization & plain formatters
    └── report.rs    # HostResult and ScanReport data models
```

---

## License

Distributed under the MIT License. See [LICENSE](LICENSE) for details.
