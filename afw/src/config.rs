use anyhow::{Context, Result};
use log::info;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

const DEFAULT_CONFIG_PATH: &str = "/etc/afw/afw.toml";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub base: BaseConfig,
    #[serde(default)]
    pub app: Vec<AppConfig>,
}

/// A drop-in config file that only contains app rules
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DropInConfig {
    #[serde(default)]
    pub app: Vec<AppConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaseConfig {
    /// Always-allowed outbound ports
    #[serde(default = "default_base_ports")]
    pub outbound: Vec<PortRule>,
    /// Allow ICMP (ping, etc.)
    #[serde(default = "default_true")]
    pub icmp: bool,
    /// Allow loopback
    #[serde(default = "default_true")]
    pub loopback: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    /// Friendly name for the application
    pub name: String,
    /// Binary/process name to match against /proc comm
    pub binary: String,
    /// Whether this app's rules are active
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Outbound port rules
    pub outbound: Vec<PortRule>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortRule {
    pub port: u16,
    /// If set, this is a port range: port-range_end
    pub range_end: Option<u16>,
    /// "tcp" or "udp"
    pub protocol: String,
}

fn default_true() -> bool {
    true
}

fn default_base_ports() -> Vec<PortRule> {
    vec![
        PortRule { port: 53, range_end: None, protocol: "udp".into() },   // DNS
        PortRule { port: 123, range_end: None, protocol: "udp".into() },  // NTP
        PortRule { port: 443, range_end: None, protocol: "tcp".into() },  // HTTPS
        PortRule { port: 80, range_end: None, protocol: "tcp".into() },   // HTTP
        PortRule { port: 68, range_end: None, protocol: "udp".into() },   // DHCP
    ]
}

/// Resolve the conf.d directory path relative to a config file path
fn conf_dir_for(config_path: &str) -> PathBuf {
    Path::new(config_path)
        .parent()
        .unwrap_or(Path::new("/etc/afw"))
        .join("conf.d")
}

impl Config {
    /// Load the main config and merge in all conf.d/*.toml drop-in files
    pub fn load(path: Option<&str>) -> Result<Self> {
        let config_path = path.unwrap_or(DEFAULT_CONFIG_PATH);
        let contents = std::fs::read_to_string(config_path)
            .with_context(|| format!("Failed to read config: {}", config_path))?;
        let mut config: Config = toml::from_str(&contents)
            .with_context(|| format!("Failed to parse config: {}", config_path))?;

        // Load drop-in configs from conf.d/
        let conf_dir = conf_dir_for(config_path);
        if conf_dir.is_dir() {
            let mut files: Vec<PathBuf> = std::fs::read_dir(&conf_dir)?
                .filter_map(|e| e.ok())
                .map(|e| e.path())
                .filter(|p| p.extension().is_some_and(|ext| ext == "toml"))
                .collect();
            files.sort(); // Alphabetical order for predictability

            for file in &files {
                let file_str = file.to_string_lossy();
                let contents = std::fs::read_to_string(file)
                    .with_context(|| format!("Failed to read drop-in config: {}", file_str))?;
                let drop_in: DropInConfig = toml::from_str(&contents)
                    .with_context(|| format!("Failed to parse drop-in config: {}", file_str))?;
                info!("Loaded drop-in config: {} ({} apps)", file_str, drop_in.app.len());
                config.app.extend(drop_in.app);
            }
        }

        Ok(config)
    }

    /// Save the base config to the main file (does not touch conf.d/)
    pub fn save(&self, path: Option<&str>) -> Result<()> {
        let config_path = path.unwrap_or(DEFAULT_CONFIG_PATH);
        let contents = toml::to_string_pretty(self)
            .context("Failed to serialize config")?;
        if let Some(parent) = Path::new(config_path).parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(config_path, contents)
            .with_context(|| format!("Failed to write config: {}", config_path))?;
        Ok(())
    }

    /// Save a full config split across the main file (base only) and conf.d/ drop-ins.
    /// Apps are written to the specified drop-in file name.
    pub fn save_apps_to_drop_in(apps: &[AppConfig], drop_in_name: &str, path: Option<&str>) -> Result<()> {
        let config_path = path.unwrap_or(DEFAULT_CONFIG_PATH);
        let conf_dir = conf_dir_for(config_path);
        std::fs::create_dir_all(&conf_dir)?;

        let drop_in = DropInConfig { app: apps.to_vec() };
        let contents = toml::to_string_pretty(&drop_in)
            .context("Failed to serialize drop-in config")?;

        let drop_in_path = conf_dir.join(format!("{}.toml", drop_in_name));
        std::fs::write(&drop_in_path, &contents)
            .with_context(|| format!("Failed to write drop-in: {}", drop_in_path.display()))?;
        Ok(())
    }

    /// Find app config by binary name
    pub fn find_app_by_binary(&self, binary: &str) -> Option<&AppConfig> {
        self.app.iter().find(|a| a.enabled && a.binary == binary)
    }

    /// Find app config by name
    pub fn find_app_by_name(&self, name: &str) -> Option<&AppConfig> {
        self.app.iter().find(|a| a.name == name)
    }

    /// Find mutable app config by name
    pub fn find_app_by_name_mut(&mut self, name: &str) -> Option<&mut AppConfig> {
        self.app.iter_mut().find(|a| a.name == name)
    }

    /// Build a lookup map: binary name -> app config index
    pub fn binary_to_app_map(&self) -> HashMap<String, usize> {
        self.app
            .iter()
            .enumerate()
            .filter(|(_, a)| a.enabled)
            .map(|(i, a)| (a.binary.clone(), i))
            .collect()
    }
}

/// Parse a port string like "443/tcp" or "50000-50100/udp" into a PortRule
pub fn parse_port_rule(s: &str) -> Result<PortRule> {
    let parts: Vec<&str> = s.split('/').collect();
    if parts.len() != 2 {
        anyhow::bail!("Invalid port format '{}', expected PORT/PROTO or PORT-PORT/PROTO", s);
    }

    let protocol = parts[1].to_lowercase();
    if protocol != "tcp" && protocol != "udp" {
        anyhow::bail!("Invalid protocol '{}', expected 'tcp' or 'udp'", protocol);
    }

    let port_part = parts[0];
    if let Some(dash_pos) = port_part.find('-') {
        let start: u16 = port_part[..dash_pos].parse()
            .with_context(|| format!("Invalid port number in '{}'", s))?;
        let end: u16 = port_part[dash_pos + 1..].parse()
            .with_context(|| format!("Invalid port number in '{}'", s))?;
        if end <= start {
            anyhow::bail!("Port range end must be greater than start in '{}'", s);
        }
        Ok(PortRule { port: start, range_end: Some(end), protocol })
    } else {
        let port: u16 = port_part.parse()
            .with_context(|| format!("Invalid port number in '{}'", s))?;
        Ok(PortRule { port, range_end: None, protocol })
    }
}
