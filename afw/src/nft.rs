use anyhow::{Context, Result};
use log::{debug, error, info};
use std::process::Command;

use crate::config::PortRule;

/// Trait for nftables operations, enabling mock testing
pub trait NftBackend: Send + Sync {
    fn add_app_rules(&self, app_name: &str, ports: &[PortRule]) -> Result<()>;
    fn remove_app_rules(&self, app_name: &str) -> Result<()>;
    fn list_rules(&self) -> Result<String>;
    fn init_table(&self, base_ports: &[PortRule], icmp: bool, loopback: bool) -> Result<()>;
    fn cleanup(&self) -> Result<()>;
}

/// Real nftables backend that executes nft commands
pub struct RealNftBackend;

impl NftBackend for RealNftBackend {
    fn init_table(&self, base_ports: &[PortRule], icmp: bool, loopback: bool) -> Result<()> {
        // Build the full table script and apply atomically via nft -f.
        // "destroy table" removes it if it exists (no error if missing),
        // then we create fresh — all in one atomic transaction so there's
        // no gap where traffic is dropped without rules.
        let rules = build_init_table_script(base_ports, icmp, loopback);
        let atomic_script = format!("destroy table inet afw\n{}", rules);
        run_nft_stdin(&atomic_script).context("Failed to initialize nftables table")?;
        info!("nftables table 'inet afw' initialized with base rules");
        Ok(())
    }

    fn add_app_rules(&self, app_name: &str, ports: &[PortRule]) -> Result<()> {
        let rules = build_add_app_rules_script(app_name, ports);
        if !rules.is_empty() {
            run_nft_stdin(&rules)
                .with_context(|| format!("Failed to add rules for app '{}'", app_name))?;
            info!("Added nftables rules for app '{}'", app_name);
        }
        Ok(())
    }

    fn remove_app_rules(&self, app_name: &str) -> Result<()> {
        let output = run_nft_output("-a list chain inet afw output")?;
        let handles = parse_rule_handles(&output, app_name);

        for handle in handles.iter().rev() {
            let cmd = format!("delete rule inet afw output handle {}", handle);
            if let Err(e) = run_nft(&cmd) {
                error!("Failed to delete rule handle {}: {}", handle, e);
            }
        }

        if !handles.is_empty() {
            info!("Removed {} nftables rules for app '{}'", handles.len(), app_name);
        }
        Ok(())
    }

    fn list_rules(&self) -> Result<String> {
        run_nft_output("list table inet afw")
    }

    fn cleanup(&self) -> Result<()> {
        run_nft("delete table inet afw").context("Failed to delete nftables table")?;
        info!("nftables table 'inet afw' removed");
        Ok(())
    }
}

// === Pure functions for script generation (testable without nft) ===

/// Build the nft script for initializing the AFW table
pub fn build_init_table_script(base_ports: &[PortRule], icmp: bool, loopback: bool) -> String {
    let mut rules = String::new();

    rules.push_str("table inet afw {\n");

    // Output chain - default drop
    rules.push_str("    chain output {\n");
    rules.push_str("        type filter hook output priority 0; policy drop;\n");
    rules.push_str("\n");
    rules.push_str("        # Allow established/related connections\n");
    rules.push_str("        ct state established,related accept\n");
    rules.push_str("\n");

    if loopback {
        rules.push_str("        # Allow loopback\n");
        rules.push_str("        oif lo accept\n");
        rules.push_str("\n");
    }

    rules.push_str("        # Base outbound rules (always allowed)\n");
    for port_rule in base_ports {
        rules.push_str(&format!("        {}\n", format_port_rule(port_rule)));
    }
    rules.push_str("\n");

    if icmp {
        rules.push_str("        # ICMP\n");
        rules.push_str("        meta l4proto icmp accept\n");
        rules.push_str("        meta l4proto icmpv6 accept\n");
        rules.push_str("\n");
    }

    rules.push_str("    }\n");
    rules.push_str("\n");

    // Input chain - default drop
    rules.push_str("    chain input {\n");
    rules.push_str("        type filter hook input priority 0; policy drop;\n");
    rules.push_str("\n");
    rules.push_str("        # Allow established/related connections\n");
    rules.push_str("        ct state established,related accept\n");
    rules.push_str("\n");

    if loopback {
        rules.push_str("        # Allow loopback\n");
        rules.push_str("        iif lo accept\n");
        rules.push_str("\n");
    }

    if icmp {
        rules.push_str("        # ICMP\n");
        rules.push_str("        meta l4proto icmp accept\n");
        rules.push_str("        meta l4proto icmpv6 accept\n");
        rules.push_str("\n");
    }

    rules.push_str("    }\n");
    rules.push_str("}\n");

    rules
}

/// Build the nft script for adding app rules
pub fn build_add_app_rules_script(app_name: &str, ports: &[PortRule]) -> String {
    let mut rules = String::new();
    for port_rule in ports {
        let rule = format_port_rule(port_rule);
        rules.push_str(&format!(
            "add rule inet afw output {} comment \"afw:{}\"\n",
            rule, app_name
        ));
    }
    rules
}

/// Parse nft rule listing output to extract handles for a given app
pub fn parse_rule_handles(output: &str, app_name: &str) -> Vec<u64> {
    let comment_tag = format!("afw:{}", app_name);
    let mut handles = Vec::new();

    for line in output.lines() {
        if line.contains(&format!("comment \"{}\"", comment_tag)) {
            if let Some(handle_str) = line.rsplit("# handle ").next() {
                if let Ok(handle) = handle_str.trim().parse::<u64>() {
                    handles.push(handle);
                }
            }
        }
    }

    handles
}

/// Format a PortRule into an nftables rule string
pub fn format_port_rule(rule: &PortRule) -> String {
    let port_spec = match rule.range_end {
        Some(end) => format!("{}-{}", rule.port, end),
        None => rule.port.to_string(),
    };

    format!("{} dport {} accept", rule.protocol, port_spec)
}

// === Private nft command execution ===

fn run_nft(args: &str) -> Result<()> {
    let status = Command::new("nft")
        .args(args.split_whitespace())
        .status()
        .context("Failed to execute nft command")?;

    if !status.success() {
        anyhow::bail!("nft command failed: nft {}", args);
    }
    Ok(())
}

fn run_nft_output(args: &str) -> Result<String> {
    let output = Command::new("nft")
        .args(args.split_whitespace())
        .output()
        .context("Failed to execute nft command")?;

    if !output.status.success() {
        anyhow::bail!(
            "nft command failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

fn run_nft_stdin(input: &str) -> Result<()> {
    use std::io::Write;
    use std::process::Stdio;

    debug!("Applying nftables rules:\n{}", input);

    let mut child = Command::new("nft")
        .arg("-f")
        .arg("-")
        .stdin(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("Failed to spawn nft")?;

    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(input.as_bytes())?;
    }

    let output = child.wait_with_output()?;
    if !output.status.success() {
        anyhow::bail!(
            "nft failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(())
}
