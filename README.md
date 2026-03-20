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

## Configuration

Base rules live in `/etc/afw/afw.toml`. App rules live in `/etc/afw/conf.d/` as drop-in files:

```
/etc/afw/
├── afw.toml              # Base rules (DNS, NTP, HTTPS, Cloudflare, etc.)
└── conf.d/
    ├── browsers.toml
    ├── communication.toml
    ├── creative.toml
    ├── development.toml
    ├── file_transfer.toml
    ├── gaming.toml
    ├── media.toml
    ├── package_managers.toml
    ├── productivity.toml
    ├── remote_desktop.toml
    ├── security.toml
    ├── system_services.toml
    ├── virtualization.toml
    └── vpn_clients.toml
```

### Example app rule

```toml
[[app]]
name = "discord"
binary = "Discord"
enabled = true
outbound = [
    { port = 443, protocol = "tcp" },
    { port = 80,  protocol = "tcp" },
    { port = 50000, range_end = 65535, protocol = "udp" },
]
```

Add a new category by dropping a `.toml` file in `conf.d/`.

## Tests

```bash
cargo test --package afw
```

278 tests covering config parsing, CLI serialization, nftables script generation, state management with mock backends, eBPF event handling, and input validation.

## Security

- Input validation prevents nftables injection via app names and port rules
- IPC commands require root (`uid 0`) for mutating operations
- Bounded IPC reads and connection limits prevent DoS
- Bounded eBPF event channel prevents OOM from fork bombs
- Config file permission checks warn on insecure ownership
- Audited against OWASP Top 10

## License

GPL-3.0-or-later
