use log::{debug, warn};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::state::UnknownConnectionSummary;

/// Directory where blocked connection logs are stored
const LOG_DIR: &str = "/var/log/afw";

/// Duration of each log slot in minutes (30-minute windows)
const SLOT_MINUTES: u32 = 30;

/// Block logger that writes blocked connection events to rotating log files.
///
/// Files are named by 30-minute time slot (e.g. `blocked-14-00.log`, `blocked-14-30.log`).
/// Since there are only 48 slots per day, each file naturally overwrites the previous
/// day's data for that same slot, keeping exactly one day's worth of logs.
pub struct BlockLogger {
    log_dir: PathBuf,
}

impl BlockLogger {
    pub fn new() -> Self {
        Self {
            log_dir: PathBuf::from(LOG_DIR),
        }
    }

    /// Ensure the log directory exists. Called once at startup.
    pub fn init(&self) {
        if let Err(e) = fs::create_dir_all(&self.log_dir) {
            warn!("Failed to create block log directory {:?}: {}", self.log_dir, e);
        }
    }

    /// Get the log file path for the current 30-minute slot.
    fn current_slot_path(&self) -> PathBuf {
        let now = chrono::Local::now();
        let slot_minute = (now.format("%M").to_string().parse::<u32>().unwrap_or(0) / SLOT_MINUTES) * SLOT_MINUTES;
        let filename = format!("blocked-{}-{:02}.log", now.format("%H"), slot_minute);
        self.log_dir.join(filename)
    }

    /// Log a blocked connection summary to the current time-slot file.
    pub fn log_blocked(&self, summary: &UnknownConnectionSummary) {
        let path = self.current_slot_path();
        let timestamp = chrono::Local::now().format("%Y-%m-%d %H:%M:%S");

        let ports_str: String = summary
            .ports
            .iter()
            .map(|(p, proto)| format!("{}/{}", p, proto))
            .collect::<Vec<_>>()
            .join(", ");

        let addrs_str: String = summary
            .dest_addrs
            .iter()
            .take(10)
            .cloned()
            .collect::<Vec<_>>()
            .join(", ");

        let line = format!(
            "[{}] BLOCKED app=\"{}\" ports=[{}] destinations=[{}] attempts={}\n",
            timestamp, summary.binary, ports_str, addrs_str, summary.attempt_count,
        );

        if let Err(e) = self.append_or_create(&path, &line) {
            warn!("Failed to write block log to {:?}: {}", path, e);
        } else {
            debug!("Logged blocked event to {:?}", path);
        }
    }

    /// Append to the file, creating or truncating if this is a new time slot
    /// (i.e., the file exists but is from a previous day).
    fn append_or_create(&self, path: &Path, line: &str) -> std::io::Result<()> {
        // If the file exists and is from a previous day, truncate it
        let should_truncate = if path.exists() {
            if let Ok(metadata) = fs::metadata(path) {
                if let Ok(modified) = metadata.modified() {
                    let age = modified.elapsed().unwrap_or_default();
                    // If the file is older than 23 hours, it's from a previous day's slot
                    age > std::time::Duration::from_secs(23 * 3600)
                } else {
                    false
                }
            } else {
                false
            }
        } else {
            false
        };

        let mut file = if should_truncate {
            OpenOptions::new()
                .write(true)
                .truncate(true)
                .create(true)
                .open(path)?
        } else {
            OpenOptions::new()
                .append(true)
                .create(true)
                .open(path)?
        };

        file.write_all(line.as_bytes())
    }
}
