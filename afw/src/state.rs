use anyhow::Result;
use log::{debug, info, warn};
use std::collections::{HashMap, HashSet};
use std::time::Instant;

use crate::config::Config;
use crate::nft::{NftBackend, RealNftBackend};

/// Binaries that should never trigger dynamic rule changes or unknown app alerts.
/// These are short-lived CLI tools, system processes, and package managers whose
/// ports are handled by the base config. Tracking them causes nft rule churn
/// that disrupts long-lived connections (WebSockets, SSE streams, etc.).
const IGNORED_BINARIES: &[&str] = &[
    // System
    "systemd",
    "systemd-resolve",
    "systemd-timesyn",
    "systemd-network",
    "kworker",
    "ksoftirqd",
    "dbus-broker",
    // Shell / CLI tools
    "git",
    "ssh",
    "scp",
    "rsync",
    "curl",
    "wget",
    "cargo",
    "go",
    "pip",
    "pip3",
    "python3",
    "python",
    "node",
    "npm",
    "npx",
    "yarn",
    "pnpm",
    // Package managers
    "pacman",
    "yay",
    "paru",
    "apt",
    "apt-get",
    "dpkg",
    "dnf",
    "yum",
    "zypper",
    "flatpak",
    "snapd",
    "snap",
    "nix",
    "brew",
    "makepkg",
    "pikaur",
    // Security updates
    "freshclam",
    // Build tools
    "cc",
    "gcc",
    "clang",
    "rustc",
    "make",
    "cmake",
    "ninja",
];

/// A connection attempt from an unknown (unconfigured) application
#[derive(Debug, Clone)]
pub struct UnknownConnection {
    /// Binary/comm name
    pub binary: String,
    /// Ports the app tried to connect to (port, protocol_str)
    pub ports: HashSet<(u16, String)>,
    /// Destination IPs seen
    pub dest_addrs: HashSet<String>,
    /// First seen
    pub first_seen: Instant,
    /// Last seen
    pub last_seen: Instant,
    /// Number of connection attempts
    pub attempt_count: u32,
    /// Whether a summary has been emitted after the aggregation window
    pub summary_emitted: bool,
}

/// Duration to wait after first seeing an unknown app before emitting a summary.
/// This aggregates all ports the app tries during this window into one report.
const AGGREGATION_WINDOW_SECS: u64 = 5;

/// Summary of an unknown app's connection attempts after the aggregation window
#[derive(Debug, Clone)]
pub struct UnknownConnectionSummary {
    pub binary: String,
    pub ports: Vec<(u16, String)>,
    pub dest_addrs: Vec<String>,
    pub attempt_count: u32,
}

impl UnknownConnectionSummary {
    /// Generate a suggested `afw add` command for this app
    pub fn suggested_command(&self) -> String {
        let port_args: Vec<String> = self
            .ports
            .iter()
            .map(|(port, proto)| format!("{}/{}", port, proto))
            .collect();
        format!(
            "afw add {} {} {}",
            self.binary.to_lowercase().replace(' ', "-"),
            self.binary,
            port_args.join(" ")
        )
    }
}

/// Runtime state tracking active processes and their firewall rules
pub struct AppState {
    /// Map of app name -> set of PIDs currently running
    active_pids: HashMap<String, HashSet<u32>>,
    /// Map of binary name -> app name for quick lookup
    binary_map: HashMap<String, String>,
    /// Current config
    config: Config,
    /// nftables backend
    nft: Box<dyn NftBackend>,
    /// Unknown apps that tried to connect (binary -> connection info)
    unknown_connections: HashMap<String, UnknownConnection>,
    /// Temporarily allowed apps (binary -> port rules, removed on exit/restart)
    temp_allowed: HashMap<String, Vec<crate::config::PortRule>>,
    /// Permanently denied apps (binary names, suppresses notifications)
    deny_list: HashSet<String>,
}

impl AppState {
    pub fn new(config: Config) -> Self {
        Self::with_backend(config, Box::new(RealNftBackend))
    }

    pub fn with_backend(config: Config, nft: Box<dyn NftBackend>) -> Self {
        let binary_map: HashMap<String, String> = config
            .app
            .iter()
            .filter(|a| a.enabled)
            .map(|a| (a.binary.clone(), a.name.clone()))
            .collect();

        Self {
            active_pids: HashMap::new(),
            binary_map,
            config,
            nft,
            unknown_connections: HashMap::new(),
            temp_allowed: HashMap::new(),
            deny_list: HashSet::new(),
        }
    }

    /// Handle a process exec event
    pub fn handle_exec(&mut self, pid: u32, comm: &str) -> Result<()> {
        let app_name = match self.binary_map.get(comm) {
            Some(name) => name.clone(),
            None => return Ok(()),
        };

        debug!(
            "Monitored app exec: {} (pid {}, binary '{}')",
            app_name, pid, comm
        );

        let pids = self.active_pids.entry(app_name.clone()).or_default();
        let was_empty = pids.is_empty();
        pids.insert(pid);

        if was_empty {
            if let Some(app_config) = self.config.find_app_by_name(&app_name) {
                info!("Opening ports for app '{}' (pid {})", app_name, pid);
                self.nft.add_app_rules(&app_name, &app_config.outbound)?;
            }
        } else {
            debug!(
                "App '{}' already active ({} instances), no rule change",
                app_name,
                pids.len()
            );
        }

        Ok(())
    }

    /// Handle a process exit event
    pub fn handle_exit(&mut self, pid: u32, comm: &str) -> Result<()> {
        // Check if this is a temp-allowed app exiting
        if self.temp_allowed.contains_key(comm) {
            // For temp-allowed apps, we don't track PIDs individually,
            // so just remove on first exit event we see
            self.remove_temp_rules(comm)?;
        }

        let app_name = match self.binary_map.get(comm) {
            Some(name) => name.clone(),
            None => return Ok(()),
        };

        debug!(
            "Monitored app exit: {} (pid {}, binary '{}')",
            app_name, pid, comm
        );

        let should_remove = if let Some(pids) = self.active_pids.get_mut(&app_name) {
            pids.remove(&pid);
            pids.is_empty()
        } else {
            false
        };

        if should_remove {
            info!(
                "Closing ports for app '{}' (last instance pid {} exited)",
                app_name, pid
            );
            self.nft.remove_app_rules(&app_name)?;
            self.active_pids.remove(&app_name);
        }

        Ok(())
    }

    /// Handle a connection attempt event from eBPF.
    /// If the app is known/configured, this is a no-op (nftables handles it).
    /// If unknown, track it for potential user approval.
    /// Returns true if this is a NEW unknown app (first time seen).
    pub fn handle_connection(
        &mut self,
        comm: &str,
        dest_port: u16,
        protocol: &str,
        dest_addr: &str,
    ) -> bool {
        // Known app — nftables already has rules, nothing to do
        if self.binary_map.contains_key(comm) {
            return false;
        }

        // Temporarily allowed app — already has rules
        if self.temp_allowed.contains_key(comm) {
            return false;
        }

        // Permanently denied — silently ignore, don't notify
        if self.deny_list.contains(comm) {
            return false;
        }

        // Skip system processes and short-lived CLI tools that use base ports.
        // These churn too fast for dynamic tracking and their ports are in base config.
        if comm.is_empty()
            || IGNORED_BINARIES.contains(&comm)
            || comm.starts_with("kworker")
            || comm.starts_with("ksoftirqd")
        {
            return false;
        }

        let now = Instant::now();
        let is_new = !self.unknown_connections.contains_key(comm);

        let entry = self
            .unknown_connections
            .entry(comm.to_string())
            .or_insert_with(|| UnknownConnection {
                binary: comm.to_string(),
                ports: HashSet::new(),
                dest_addrs: HashSet::new(),
                first_seen: now,
                last_seen: now,
                attempt_count: 0,
                summary_emitted: false,
            });

        entry.ports.insert((dest_port, protocol.to_string()));
        entry.dest_addrs.insert(dest_addr.to_string());
        entry.last_seen = now;
        entry.attempt_count += 1;

        if is_new {
            warn!(
                "Unknown app '{}' attempted connection to {}:{}/{}",
                comm, dest_addr, dest_port, protocol
            );
        } else {
            debug!(
                "Unknown app '{}' connection attempt #{} to {}:{}/{}",
                comm, entry.attempt_count, dest_addr, dest_port, protocol
            );
        }

        is_new
    }

    /// Get all unknown connection attempts
    pub fn unknown_connections(&self) -> &HashMap<String, UnknownConnection> {
        &self.unknown_connections
    }

    /// Get unknown connections summary for display
    pub fn unknown_connections_info(&self) -> String {
        let mut out = String::new();

        if !self.temp_allowed.is_empty() {
            out.push_str(&format!(
                "Temporarily allowed: {}\n",
                self.temp_allowed.len()
            ));
            for (binary, rules) in &self.temp_allowed {
                let ports: Vec<String> = rules
                    .iter()
                    .map(|r| format!("{}/{}", r.port, r.protocol))
                    .collect();
                out.push_str(&format!("  {} [{}]\n", binary, ports.join(", ")));
            }
            out.push('\n');
        }

        if !self.deny_list.is_empty() {
            out.push_str(&format!("Permanently denied: {}\n", self.deny_list.len()));
            for binary in &self.deny_list {
                out.push_str(&format!("  {}\n", binary));
            }
            out.push('\n');
        }

        if self.unknown_connections.is_empty() {
            if self.temp_allowed.is_empty() && self.deny_list.is_empty() {
                out.push_str("No unknown connection attempts.\n");
            }
            return out;
        }

        out.push_str(&format!(
            "Blocked unknown apps: {}\n\n",
            self.unknown_connections.len()
        ));

        let mut entries: Vec<_> = self.unknown_connections.values().collect();
        entries.sort_by(|a, b| b.attempt_count.cmp(&a.attempt_count));

        for conn in entries {
            let elapsed = conn.first_seen.elapsed().as_secs();
            let status = if conn.summary_emitted {
                "aggregated"
            } else {
                "collecting..."
            };
            out.push_str(&format!(
                "  {} ({} attempts, {}s ago) [{}]\n",
                conn.binary, conn.attempt_count, elapsed, status
            ));

            let mut ports: Vec<_> = conn.ports.iter().collect();
            ports.sort_by_key(|(p, _)| *p);
            for (port, proto) in &ports {
                out.push_str(&format!("    -> {}/{}\n", port, proto));
            }

            if !conn.dest_addrs.is_empty() {
                let addrs: Vec<_> = conn.dest_addrs.iter().take(5).cloned().collect();
                let suffix = if conn.dest_addrs.len() > 5 {
                    format!(" (+{} more)", conn.dest_addrs.len() - 5)
                } else {
                    String::new()
                };
                out.push_str(&format!("    IPs: {}{}\n", addrs.join(", "), suffix));
            }

            // Suggest the add command
            let port_args: Vec<String> = ports
                .iter()
                .map(|(port, proto)| format!("{}/{}", port, proto))
                .collect();
            if !port_args.is_empty() {
                out.push_str(&format!(
                    "    Suggest: afw add {} {} {}\n",
                    conn.binary.to_lowercase().replace(' ', "-"),
                    conn.binary,
                    port_args.join(" ")
                ));
            }
            out.push('\n');
        }

        out
    }

    /// Check aggregation windows and return summaries for apps ready to report.
    /// An app is "ready" when it was first seen >= AGGREGATION_WINDOW_SECS ago
    /// and hasn't had a summary emitted yet.
    pub fn check_aggregation_windows(&mut self) -> Vec<UnknownConnectionSummary> {
        let mut summaries = Vec::new();

        for conn in self.unknown_connections.values_mut() {
            if !conn.summary_emitted
                && conn.first_seen.elapsed().as_secs() >= AGGREGATION_WINDOW_SECS
            {
                conn.summary_emitted = true;

                let mut ports: Vec<(u16, String)> = conn.ports.iter().cloned().collect();
                ports.sort_by_key(|(p, _)| *p);

                summaries.push(UnknownConnectionSummary {
                    binary: conn.binary.clone(),
                    ports,
                    dest_addrs: conn.dest_addrs.iter().cloned().collect(),
                    attempt_count: conn.attempt_count,
                });
            }
        }

        summaries
    }

    /// Clear unknown connection tracking for a specific app (e.g. after approval)
    pub fn clear_unknown(&mut self, binary: &str) {
        self.unknown_connections.remove(binary);
    }

    /// Temporarily allow an app (rules added now, removed on exit or daemon restart).
    /// Uses the ports detected in unknown_connections.
    pub fn allow_once(&mut self, binary: &str) -> Result<Option<Vec<crate::config::PortRule>>> {
        let conn = match self.unknown_connections.get(binary) {
            Some(c) => c.clone(),
            None => return Ok(None),
        };

        // Validate binary name before using it in nftables rules to prevent injection
        let app_name = binary.to_lowercase().replace(' ', "-");
        crate::config::validate_name(&app_name)?;
        crate::config::validate_name(binary)?;

        let port_rules: Vec<crate::config::PortRule> = conn
            .ports
            .iter()
            .map(|(port, proto)| crate::config::PortRule {
                port: *port,
                range_end: None,
                protocol: proto.clone(),
            })
            .collect();

        if port_rules.is_empty() {
            return Ok(None);
        }

        info!(
            "Temporarily allowing '{}' with {} port(s)",
            binary,
            port_rules.len()
        );
        self.nft.add_app_rules(&app_name, &port_rules)?;
        self.temp_allowed
            .insert(binary.to_string(), port_rules.clone());
        self.unknown_connections.remove(binary);

        Ok(Some(port_rules))
    }

    /// Remove temporary rules for an app (called on exit or cleanup)
    pub fn remove_temp_rules(&mut self, binary: &str) -> Result<()> {
        if self.temp_allowed.remove(binary).is_some() {
            let app_name = binary.to_lowercase().replace(' ', "-");
            info!("Removing temporary rules for '{}'", binary);
            self.nft.remove_app_rules(&app_name)?;
        }
        Ok(())
    }

    /// Add a binary to the permanent deny list
    pub fn deny_app(&mut self, binary: &str) {
        info!("Permanently denying '{}'", binary);
        self.deny_list.insert(binary.to_string());
        self.unknown_connections.remove(binary);
    }

    /// Remove a binary from the deny list
    pub fn undeny_app(&mut self, binary: &str) {
        self.deny_list.remove(binary);
    }

    /// Check if a binary is denied
    pub fn is_denied(&self, binary: &str) -> bool {
        self.deny_list.contains(binary)
    }

    /// Get the deny list
    pub fn deny_list(&self) -> &HashSet<String> {
        &self.deny_list
    }

    /// Get temporarily allowed apps
    pub fn temp_allowed(&self) -> &HashMap<String, Vec<crate::config::PortRule>> {
        &self.temp_allowed
    }

    /// Scan /proc for already-running monitored processes
    pub fn scan_existing_processes(&mut self) -> Result<()> {
        info!("Scanning /proc for already-running monitored apps...");
        let proc_dir = std::fs::read_dir("/proc")?;

        for entry in proc_dir.flatten() {
            let name = entry.file_name();
            let name_str = name.to_string_lossy();

            if let Ok(pid) = name_str.parse::<u32>() {
                let comm_path = format!("/proc/{}/comm", pid);
                if let Ok(comm) = std::fs::read_to_string(&comm_path) {
                    let comm = comm.trim();
                    if self.binary_map.contains_key(comm) {
                        self.handle_exec(pid, comm)?;
                    }
                }
            }
        }

        Ok(())
    }

    /// Reload config and update state
    pub fn reload_config(&mut self, config: Config) -> Result<()> {
        let old_apps: HashSet<String> = self.binary_map.values().cloned().collect();
        let new_binary_map: HashMap<String, String> = config
            .app
            .iter()
            .filter(|a| a.enabled)
            .map(|a| (a.binary.clone(), a.name.clone()))
            .collect();
        let new_apps: HashSet<String> = new_binary_map.values().cloned().collect();

        for app_name in old_apps.difference(&new_apps) {
            if self.active_pids.contains_key(app_name) {
                info!(
                    "App '{}' removed/disabled in config, closing ports",
                    app_name
                );
                self.nft.remove_app_rules(app_name)?;
                self.active_pids.remove(app_name);
            }
        }

        self.config = config;
        self.binary_map = new_binary_map;

        self.scan_existing_processes()?;

        info!("Config reloaded successfully");
        Ok(())
    }

    /// Get current status info
    pub fn status_info(&self) -> String {
        let mut out = String::new();
        out.push_str(crate::banner::STATUS_HEADER);
        out.push_str("  ─────────────────────────\n\n");

        out.push_str(&format!("Monitored apps: {}\n", self.config.app.len()));

        let active_count = self.active_pids.values().filter(|p| !p.is_empty()).count();
        out.push_str(&format!("Active apps:    {}\n\n", active_count));

        if self.active_pids.is_empty() {
            out.push_str("No monitored applications currently running.\n");
        } else {
            for (app_name, pids) in &self.active_pids {
                if !pids.is_empty() {
                    out.push_str(&format!(
                        "  {} - {} instance(s) (PIDs: {:?})\n",
                        app_name,
                        pids.len(),
                        pids
                    ));
                    if let Some(app) = self.config.find_app_by_name(app_name) {
                        for port in &app.outbound {
                            let port_str = match port.range_end {
                                Some(end) => format!("{}-{}/{}", port.port, end, port.protocol),
                                None => format!("{}/{}", port.port, port.protocol),
                            };
                            out.push_str(&format!("    → {}\n", port_str));
                        }
                    }
                }
            }
        }

        out
    }

    /// Get config reference
    pub fn config(&self) -> &Config {
        &self.config
    }

    /// Get nft backend reference
    pub fn nft(&self) -> &dyn NftBackend {
        &*self.nft
    }
}
