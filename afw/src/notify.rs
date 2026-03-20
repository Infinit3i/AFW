use log::{debug, error, info};
use std::collections::HashMap;
use std::process::Command;
use std::time::Instant;

use crate::state::UnknownConnectionSummary;

/// Minimum seconds between notifications for the same app
const RATE_LIMIT_SECS: u64 = 30;

/// Action chosen by the user from a notification
#[derive(Debug, Clone, PartialEq)]
pub enum NotifyAction {
    /// Permanently allow (save to config)
    Approve,
    /// Temporarily allow (removed on exit/restart)
    AllowOnce,
    /// Permanently deny (suppress future notifications)
    Deny,
    /// User dismissed or notification timed out
    Dismissed,
}

/// Desktop notification sender with action button support
pub struct Notifier {
    /// Track when we last notified for each binary (rate limiting)
    last_notified: HashMap<String, Instant>,
    /// Cached desktop session info (user, env vars)
    session_cache: Option<(String, HashMap<String, String>)>,
    /// Whether session detection has been attempted
    session_detected: bool,
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
            session_cache: None,
            session_detected: false,
        }
    }

    /// Send a desktop notification with action buttons for a blocked app.
    /// Returns the user's chosen action, or None if notification couldn't be sent.
    /// Rate-limited to one notification per app per RATE_LIMIT_SECS.
    pub fn notify_blocked_app(
        &mut self,
        summary: &UnknownConnectionSummary,
    ) -> Option<NotifyAction> {
        // Rate limit
        if let Some(last) = self.last_notified.get(&summary.binary) {
            if last.elapsed().as_secs() < RATE_LIMIT_SECS {
                debug!(
                    "Skipping notification for '{}' (rate limited)",
                    summary.binary
                );
                return None;
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
            "Blocked {} connection attempt(s)\nPorts: {}",
            summary.attempt_count, port_list,
        );

        // Detect desktop session (cached after first attempt)
        if !self.session_detected {
            self.session_cache = find_desktop_session();
            self.session_detected = true;
        }

        let (user, env_vars) = match &self.session_cache {
            Some((u, e)) => (u.clone(), e.clone()),
            None => {
                info!(
                    "No desktop session available for notification. Use `afw pending` to review."
                );
                return None;
            }
        };

        // Try interactive notification with action buttons
        let action = send_interactive_notification(&user, &env_vars, &title, &body);
        debug!("Notification action for '{}': {:?}", summary.binary, action);
        Some(action)
    }
}

/// Send a notification with action buttons via notify-send.
/// Blocks until the user clicks a button or the notification times out.
fn send_interactive_notification(
    user: &str,
    env_vars: &HashMap<String, String>,
    title: &str,
    body: &str,
) -> NotifyAction {
    // Try notify-send with --action flags (requires libnotify >= 0.8)
    let mut cmd = Command::new("sudo");
    cmd.args(["-u", user, "notify-send"]);
    cmd.args([
        "--app-name=AFW",
        "--urgency=critical",
        "--icon=security-high",
        "--wait",
        "--action=approve=Always Allow",
        "--action=allow_once=Allow Once",
        "--action=deny=Deny",
    ]);
    cmd.arg(title);
    cmd.arg(body);

    for (key, val) in env_vars {
        cmd.env(key, val);
    }

    match cmd.output() {
        Ok(output) => {
            if output.status.success() {
                let action_id = String::from_utf8_lossy(&output.stdout).trim().to_string();
                return match action_id.as_str() {
                    "approve" => NotifyAction::Approve,
                    "allow_once" => NotifyAction::AllowOnce,
                    "deny" => NotifyAction::Deny,
                    _ => NotifyAction::Dismissed,
                };
            }
            debug!(
                "notify-send exited with {}: {}",
                output.status,
                String::from_utf8_lossy(&output.stderr)
            );

            // Fallback: try without actions (older notify-send or no action support)
            send_simple_notification(user, env_vars, title, body);
            NotifyAction::Dismissed
        }
        Err(e) => {
            error!("Failed to run notify-send: {}", e);
            NotifyAction::Dismissed
        }
    }
}

/// Send a simple notification without action buttons (fallback)
fn send_simple_notification(
    user: &str,
    env_vars: &HashMap<String, String>,
    title: &str,
    body: &str,
) {
    let mut cmd = Command::new("sudo");
    cmd.args(["-u", user, "notify-send"]);
    cmd.args([
        "--app-name=AFW",
        "--urgency=critical",
        "--icon=security-high",
    ]);
    cmd.arg(title);
    cmd.arg(format!("{}\nUse `afw pending` to review", body));

    for (key, val) in env_vars {
        cmd.env(key, val);
    }

    if let Err(e) = cmd.output() {
        debug!("Simple notification also failed: {}", e);
    }
}

/// Find a logged-in desktop user's session and return (username, env_vars).
fn find_desktop_session() -> Option<(String, HashMap<String, String>)> {
    let proc_dir = match std::fs::read_dir("/proc") {
        Ok(d) => d,
        Err(_) => return None,
    };

    for entry in proc_dir.flatten() {
        let name = entry.file_name();
        let name_str = name.to_string_lossy();

        if name_str.parse::<u32>().is_err() {
            continue;
        }

        let pid_path = entry.path();
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

        if uid == 0 {
            continue;
        }

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

        let has_display =
            env_pairs.contains_key("DISPLAY") || env_pairs.contains_key("WAYLAND_DISPLAY");
        let has_dbus = env_pairs.contains_key("DBUS_SESSION_BUS_ADDRESS");

        if has_display && has_dbus {
            let username = get_username(uid).unwrap_or_else(|| format!("#{}", uid));

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

            return Some((username, session_env));
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
