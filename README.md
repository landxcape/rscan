# rscan 🛡️

**A high-performance, asynchronous Layer 2 network discovery and security auditing tool written in Rust.**

`rscan` combines low-level ARP scanning with high-concurrency TCP port probing to provide a clear, real-time snapshot of your local network. It doesn't just find IP addresses; it identifies the hardware manufacturers and the services running on them.

---

## 🚀 Features

-   **Layer 2 Discovery:** Fast ARP-based host discovery across CIDR blocks.
-   **Parallel Port Scanning:** Concurrent TCP probing for common services (SSH, HTTP, SMB, RDP, etc.).
-   **Vendor Identification:** Automatic MAC address OUI lookup to identify device manufacturers (e.g., Apple, Dell, Cisco).
-   **Smart Auto-Discovery:** Intelligently selects the best network interface based on IPv4 connectivity.
-   **Asynchronous Architecture:** Built on `tokio` for non-blocking I/O and high performance.
-   **Robust Safety:** Enforces administrative privileges early to ensure raw socket operations succeed.

---

## 🛠️ Installation

### Prerequisites
- **Rust Toolchain:** Ensure you have the latest stable [Rust](https://rustup.rs/) installed.
- **Administrative Privileges:** `rscan` requires raw socket access for ARP scanning.

### Build from Source
```bash
git clone https://github.com/landxcape/rscan.git
cd rscan
cargo build --release
```

The binary will be available at `./target/release/rscan`.

---

## 📖 Usage

### Basic Scan
Scan a target subnet using the best available interface:
```bash
sudo ./target/release/rscan --target 192.168.1.0/24
```

### List Interfaces
View available network interfaces and their configuration:
```bash
sudo ./target/release/rscan --list-interfaces
```

### Specify Interface
Bind to a specific interface:
```bash
sudo ./target/release/rscan --target 10.0.0.0/24 --interface eth0
```

---

## 🏗️ Technical Architecture

`rscan` is built for efficiency and reliability:
- **`pnet`**: Utilized for raw datalink layer frame construction and packet capture.
- **`tokio`**: Orchestrates the asynchronous scanning loop and background listener.
- **`anyhow`**: Provides robust, context-aware error propagation.
- **`manuf`**: Powers the offline OUI vendor identification database.

The tool uses a **synchronous-to-async bridge**: a dedicated background thread handles the blocking packet capture, while the main loop asynchronously broadcasts requests and processes results in real-time.

---

## ⚖️ License
This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## 🤝 Contributing
Contributions are welcome! Please feel free to submit a Pull Request.
