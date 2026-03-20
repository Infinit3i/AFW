# AFW - Application Firewall

```
 █████╗ ███████╗██╗    ██╗
██╔══██╗██╔════╝██║    ██║
███████║█████╗  ██║ █╗ ██║
██╔══██║██╔══╝  ██║███╗██║
██║  ██║██║     ╚███╔███╔╝
╚═╝  ╚═╝╚═╝      ╚══╝╚══╝
```

eBPF-powered per-application outbound firewall for Linux. Monitors process exec/exit via kernel tracepoints and dynamically manages nftables rules — ports open when an app starts and close when it exits.

## How It Works

1. eBPF tracepoints watch `sched_process_exec` and `sched_process_exit`
2. When a monitored app starts, its outbound port rules are added to nftables
3. When the last instance exits, the rules are removed
4. Default policy is **drop** — only explicitly allowed traffic gets through

## Install

### Prerequisites

- Linux kernel with eBPF support
- `nftables`
- Rust stable + nightly (for eBPF compilation)
- `bpf-linker`

```bash
# Install Rust toolchains
rustup toolchain install nightly
rustup component add rust-src --toolchain nightly
cargo +nightly install bpf-linker
```

### Build

```bash
cargo xtask build-ebpf --release
cargo build --package afw --release
```

### Setup

```bash
sudo mkdir -p /etc/afw/conf.d
sudo cp config/afw.toml /etc/afw/
sudo cp -r config/conf.d/* /etc/afw/conf.d/
sudo cp systemd/afw.service /etc/systemd/system/
sudo systemctl daemon-reload
```

### Run

```bash
# Start directly
sudo ./target/release/afw daemon

# Or via systemd
sudo systemctl start afw
sudo systemctl enable afw
```

## Usage

```bash
afw status              # Show active apps and open ports
afw list                # List all configured applications
afw rules               # Show current nftables rules
afw add <name> <binary> <ports...>   # Add an app rule
afw remove <name>       # Remove an app rule
afw enable <name>       # Enable an app
afw disable <name>      # Disable an app
afw reload              # Reload config from disk
```

## License

GPL-3.0-or-later
