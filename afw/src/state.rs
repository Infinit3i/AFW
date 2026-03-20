use anyhow::Result;
use log::{debug, info};
use std::collections::{HashMap, HashSet};

use crate::config::Config;
use crate::nft::{NftBackend, RealNftBackend};

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
        out.push_str("AFW Status\n");
        out.push_str("══════════\n\n");

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
