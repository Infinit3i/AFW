use log::{debug, info};
use std::collections::HashMap;
use std::process::Command;
use std::time::Instant;

use crate::state::UnknownConnectionSummary;

/// Minimum seconds between notifications for the same app
const RATE_LIMIT_SECS: u64 = 30;

/// Desktop notification sender
pub struct Notifier {
    /// Track when we last notified for each binary (rate limiting)
    last_notified: HashMap<String, Instant>,
}

impl Default for Notifier {
    fn default() -> Self {
        Self::new()
    }
}

impl Notifier {
    pub fn new() -> Self {
        Self {
            last_notified: HashMap::new(),
        }
    }

    /// Send a desktop notification for a blocked unknown app.
    /// Rate-limited to one notification per app per RATE_LIMIT_SECS.
    pub fn notify_blocked_app(&mut self, summary: &UnknownConnectionSummary) {
        // Rate limit
        if let Some(last) = self.last_notified.get(&summary.binary) {
            if last.elapsed().as_secs() < RATE_LIMIT_SECS {
                debug!(
                    "Skipping notification for '{}' (rate limited)",
                    summary.binary
                );
                return;
            }
        }
        self.last_notified
            .insert(summary.binary.clone(), Instant::now());

        let port_list: String = summary
            .ports
            .iter()
            .map(|(p, proto)| format!("{}/{}", p, proto))
            .collect::<Vec<_>>()
            .join(", ");

        let title = format!("AFW Blocked: {}", summary.binary);
        let body = format!(
            "Blocked {} connection attempt(s)\nPorts: {}\nTo allow: {}",
            summary.attempt_count,
            port_list,
            summary.suggested_command()
        );

        // Try to send desktop notification
        if !try_notify_send(&title, &body) {
            // Fallback: just log it (already logged by daemon, but mark it)
            info!("No desktop session available for notification. Use `afw pending` to review.");
        }
    }
}

/// Try to send a notification via notify-send using the logged-in user's session.
/// Returns true if notification was sent successfully.
fn try_notify_send(title: &str, body: &str) -> bool {
    // Find the first graphical user session
    if let Some((uid, user, env_vars)) = find_desktop_session() {
        debug!("Sending notification to user '{}' (uid {})", user, uid);

        let mut cmd = Command::new("sudo");
        cmd.args(["-u", &user, "notify-send"]);
        cmd.args([
            "--app-name=AFW",
            "--urgency=critical",
            "--icon=security-high",
        ]);
        cmd.arg(title);
        cmd.arg(body);

        // Pass the user's display/dbus environment
        for (key, val) in &env_vars {
            cmd.env(key, val);
        }

        match cmd.output() {
            Ok(output) => {
                if output.status.success() {
                    debug!("Desktop notification sent successfully");
                    return true;
                }
                debug!(
                    "notify-send failed: {}",
                    String::from_utf8_lossy(&output.stderr)
                );
            }
            Err(e) => {
                debug!("Failed to run notify-send: {}", e);
            }
        }
    }

    false
}

/// Find a logged-in desktop user's session and return (uid, username, env_vars).
/// Looks for DISPLAY or WAYLAND_DISPLAY in /proc to find a graphical session.
fn find_desktop_session() -> Option<(u32, String, HashMap<String, String>)> {
    // Strategy: find a process with DISPLAY or WAYLAND_DISPLAY set
    // by scanning /proc/*/environ for non-root users
    let proc_dir = match std::fs::read_dir("/proc") {
        Ok(d) => d,
        Err(_) => return None,
    };

    for entry in proc_dir.flatten() {
        let name = entry.file_name();
        let name_str = name.to_string_lossy();

        // Only numeric dirs (PIDs)
        if name_str.parse::<u32>().is_err() {
            continue;
        }

        let pid_path = entry.path();

        // Check process owner
        let status_path = pid_path.join("status");
        let status = match std::fs::read_to_string(&status_path) {
            Ok(s) => s,
            Err(_) => continue,
        };

        let uid: u32 = status
            .lines()
            .find(|l| l.starts_with("Uid:"))
            .and_then(|l| l.split_whitespace().nth(1))
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);

        // Skip root
        if uid == 0 {
            continue;
        }

        // Read environ for display variables
        let environ_path = pid_path.join("environ");
        let environ = match std::fs::read(&environ_path) {
            Ok(bytes) => bytes,
            Err(_) => continue,
        };

        let env_str = String::from_utf8_lossy(&environ);
        let env_pairs: HashMap<String, String> = env_str
            .split('\0')
            .filter_map(|s| {
                let (key, val) = s.split_once('=')?;
                Some((key.to_string(), val.to_string()))
            })
            .collect();

        // Look for a graphical session
        let has_display =
            env_pairs.contains_key("DISPLAY") || env_pairs.contains_key("WAYLAND_DISPLAY");
        let has_dbus = env_pairs.contains_key("DBUS_SESSION_BUS_ADDRESS");

        if has_display && has_dbus {
            // Get the username
            let username = get_username(uid).unwrap_or_else(|| format!("#{}", uid));

            // Collect the relevant env vars
            let mut session_env = HashMap::new();
            for key in &[
                "DISPLAY",
                "WAYLAND_DISPLAY",
                "DBUS_SESSION_BUS_ADDRESS",
                "XDG_RUNTIME_DIR",
            ] {
                if let Some(val) = env_pairs.get(*key) {
                    session_env.insert(key.to_string(), val.clone());
                }
            }

            return Some((uid, username, session_env));
        }
    }

    None
}

/// Get username from uid via /etc/passwd
fn get_username(uid: u32) -> Option<String> {
    let passwd = std::fs::read_to_string("/etc/passwd").ok()?;
    for line in passwd.lines() {
        let parts: Vec<&str> = line.split(':').collect();
        if parts.len() >= 3 {
            if let Ok(entry_uid) = parts[2].parse::<u32>() {
                if entry_uid == uid {
                    return Some(parts[0].to_string());
                }
            }
        }
    }
    None
}
