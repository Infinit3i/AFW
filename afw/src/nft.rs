use anyhow::{Context, Result};
use log::{debug, error, info};
use std::process::Command;

use crate::config::PortRule;

const TABLE_NAME: &str = "afw";
const TABLE_FAMILY: &str = "inet";

/// Initialize the AFW nftables table with base rules
pub fn init_table(base_ports: &[PortRule], icmp: bool, loopback: bool) -> Result<()> {
    // Delete existing table if present (clean slate)
    let _ = run_nft("delete table inet afw");

    // Build the full ruleset as an nft script
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

    // Base port rules
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

    run_nft_stdin(&rules).context("Failed to initialize nftables table")?;
    info!("nftables table 'inet afw' initialized with base rules");
    Ok(())
}

/// Add dynamic outbound rules for an application
pub fn add_app_rules(app_name: &str, ports: &[PortRule]) -> Result<()> {
    let mut rules = String::new();

    for port_rule in ports {
        let rule = format_port_rule(port_rule);
        rules.push_str(&format!(
            "add rule inet afw output {} comment \"afw:{}\"\n",
            rule, app_name
        ));
    }

    if !rules.is_empty() {
        run_nft_stdin(&rules)
            .with_context(|| format!("Failed to add rules for app '{}'", app_name))?;
        info!("Added nftables rules for app '{}'", app_name);
    }
    Ok(())
}

/// Remove dynamic outbound rules for an application
pub fn remove_app_rules(app_name: &str) -> Result<()> {
    // List rules with handles to find our tagged rules
    let output = run_nft_output("list chain inet afw output -a")?;

    let comment_tag = format!("afw:{}", app_name);
    let mut handles = Vec::new();

    for line in output.lines() {
        if line.contains(&format!("comment \"{}\"", comment_tag)) {
            // Extract handle number from "# handle N"
            if let Some(handle_str) = line.rsplit("# handle ").next() {
                if let Ok(handle) = handle_str.trim().parse::<u64>() {
                    handles.push(handle);
                }
            }
        }
    }

    // Remove rules by handle (in reverse order to keep handles valid)
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

/// Clean up: delete the entire AFW table
pub fn cleanup() -> Result<()> {
    run_nft("delete table inet afw").context("Failed to delete nftables table")?;
    info!("nftables table 'inet afw' removed");
    Ok(())
}

/// Get current AFW rules as a string
pub fn list_rules() -> Result<String> {
    run_nft_output("list table inet afw")
}

/// Format a PortRule into an nftables rule string (without the accept keyword for base,
/// but with accept for the full rule)
fn format_port_rule(rule: &PortRule) -> String {
    let port_spec = match rule.range_end {
        Some(end) => format!("{}-{}", rule.port, end),
        None => rule.port.to_string(),
    };

    format!("{} dport {} accept", rule.protocol, port_spec)
}

/// Run an nft command
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

/// Run an nft command and capture output
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

/// Run nft with rules from stdin
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
