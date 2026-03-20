use clap::Parser;
use serde::{Deserialize, Serialize};

#[derive(Parser)]
#[command(
    name = "afw",
    about = "AFW - Application Firewall\n\n  eBPF-powered per-application outbound firewall for Linux.\n  Monitors process exec/exit and dynamically manages nftables rules.",
    version,
    before_help = r#"
 █████╗ ███████╗██╗    ██╗
██╔══██╗██╔════╝██║    ██║
███████║█████╗  ██║ █╗ ██║
██╔══██║██╔══╝  ██║███╗██║
██║  ██║██║     ╚███╔███╔╝
╚═╝  ╚═╝╚═╝      ╚══╝╚══╝
"#
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Parser, Serialize, Deserialize, Debug, Clone)]
pub enum Command {
    /// Run the AFW daemon (used by systemd)
    Daemon,

    /// Show current status: active apps, open ports
    Status,

    /// List all configured applications
    List,

    /// Add a new application rule
    Add {
        /// Application name (e.g., "discord")
        name: String,
        /// Binary/process name to match (e.g., "Discord")
        binary: String,
        /// Outbound ports to allow (e.g., "443/tcp" "50000-50100/udp")
        #[arg(required = true, num_args = 1..)]
        ports: Vec<String>,
    },

    /// Remove an application rule
    Remove {
        /// Application name to remove
        name: String,
    },

    /// Enable an application's firewall rules
    Enable {
        /// Application name to enable
        name: String,
    },

    /// Disable an application's firewall rules
    Disable {
        /// Application name to disable
        name: String,
    },

    /// Reload configuration from disk
    Reload,

    /// Show current nftables rules managed by AFW
    Rules,

    /// Show unknown apps that attempted connections (blocked by default-drop)
    Pending,

    /// Approve a blocked unknown app (auto-adds rules based on detected ports)
    Approve {
        /// Binary/process name to approve (as shown in `afw pending`)
        binary: String,
    },
}

/// Response from daemon to CLI
#[derive(Serialize, Deserialize, Debug)]
pub struct DaemonResponse {
    pub success: bool,
    pub message: String,
}
