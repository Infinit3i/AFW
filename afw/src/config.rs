use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

const DEFAULT_CONFIG_PATH: &str = "/etc/afw/afw.toml";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub base: BaseConfig,
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

impl Config {
    /// Load config from the default path or a specified path
    pub fn load(path: Option<&str>) -> Result<Self> {
        let config_path = path.unwrap_or(DEFAULT_CONFIG_PATH);
        let contents = std::fs::read_to_string(config_path)
            .with_context(|| format!("Failed to read config: {}", config_path))?;
        let config: Config = toml::from_str(&contents)
            .with_context(|| format!("Failed to parse config: {}", config_path))?;
        Ok(config)
    }

    /// Save config to disk
    pub fn save(&self, path: Option<&str>) -> Result<()> {
        let config_path = path.unwrap_or(DEFAULT_CONFIG_PATH);
        let contents = toml::to_string_pretty(self)
            .context("Failed to serialize config")?;
        // Ensure parent directory exists
        if let Some(parent) = Path::new(config_path).parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(config_path, contents)
            .with_context(|| format!("Failed to write config: {}", config_path))?;
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
