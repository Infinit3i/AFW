use anyhow::{Context, Result};
use log::{debug, error, info};
use serde_json;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::Mutex;

use crate::cli::{Command, DaemonResponse};
use crate::config::{self, Config};
use crate::state::AppState;

const SOCKET_PATH: &str = "/run/afw/afw.sock";

/// Start the IPC server (called by daemon)
pub async fn start_server(state: Arc<Mutex<AppState>>) -> Result<()> {
    // Clean up old socket
    let _ = std::fs::remove_file(SOCKET_PATH);

    // Ensure directory exists
    std::fs::create_dir_all("/run/afw")?;

    let listener = UnixListener::bind(SOCKET_PATH)
        .with_context(|| format!("Failed to bind socket at {}", SOCKET_PATH))?;

    // Set permissions so non-root users can query status
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(SOCKET_PATH, std::fs::Permissions::from_mode(0o660))?;
    }

    info!("IPC server listening on {}", SOCKET_PATH);

    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                let state = Arc::clone(&state);
                tokio::spawn(async move {
                    if let Err(e) = handle_client(stream, state).await {
                        error!("Error handling IPC client: {}", e);
                    }
                });
            }
            Err(e) => {
                error!("Error accepting IPC connection: {}", e);
            }
        }
    }
}

async fn handle_client(stream: UnixStream, state: Arc<Mutex<AppState>>) -> Result<()> {
    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);
    let mut line = String::new();
    reader.read_line(&mut line).await?;

    let cmd: Command =
        serde_json::from_str(line.trim()).context("Failed to parse command from client")?;

    debug!("Received IPC command: {:?}", cmd);

    let response = process_command(cmd, state).await;

    let response_json = serde_json::to_string(&response)?;
    writer.write_all(response_json.as_bytes()).await?;
    writer.write_all(b"\n").await?;
    writer.shutdown().await?;

    Ok(())
}

async fn process_command(cmd: Command, state: Arc<Mutex<AppState>>) -> DaemonResponse {
    match cmd {
        Command::Status => {
            let state = state.lock().await;
            DaemonResponse {
                success: true,
                message: state.status_info(),
            }
        }
        Command::List => {
            let state = state.lock().await;
            let config = state.config();
            let mut msg = String::new();
            msg.push_str("Configured Applications\n");
            msg.push_str("═══════════════════════\n\n");

            if config.app.is_empty() {
                msg.push_str("No applications configured.\n");
            } else {
                for app in &config.app {
                    let status = if app.enabled { "enabled" } else { "disabled" };
                    msg.push_str(&format!(
                        "  {} [{}] (binary: {})\n",
                        app.name, status, app.binary
                    ));
                    for port in &app.outbound {
                        let port_str = match port.range_end {
                            Some(end) => format!("{}-{}/{}", port.port, end, port.protocol),
                            None => format!("{}/{}", port.port, port.protocol),
                        };
                        msg.push_str(&format!("    → {}\n", port_str));
                    }
                }
            }

            DaemonResponse {
                success: true,
                message: msg,
            }
        }
        Command::Add {
            name,
            binary,
            ports,
        } => {
            let port_rules: Result<Vec<_>, _> =
                ports.iter().map(|p| config::parse_port_rule(p)).collect();
            match port_rules {
                Ok(port_rules) => {
                    let mut state = state.lock().await;
                    let mut config = state.config().clone();
                    // Check if already exists
                    if config.find_app_by_name(&name).is_some() {
                        return DaemonResponse {
                            success: false,
                            message: format!("App '{}' already exists. Remove it first.", name),
                        };
                    }
                    config.app.push(config::AppConfig {
                        name: name.clone(),
                        binary,
                        enabled: true,
                        outbound: port_rules,
                    });
                    if let Err(e) = config.save(None) {
                        return DaemonResponse {
                            success: false,
                            message: format!("Failed to save config: {}", e),
                        };
                    }
                    if let Err(e) = state.reload_config(config) {
                        return DaemonResponse {
                            success: false,
                            message: format!("Failed to reload: {}", e),
                        };
                    }
                    DaemonResponse {
                        success: true,
                        message: format!("Added app '{}'", name),
                    }
                }
                Err(e) => DaemonResponse {
                    success: false,
                    message: format!("Invalid port format: {}", e),
                },
            }
        }
        Command::Remove { name } => {
            let mut state = state.lock().await;
            let mut config = state.config().clone();
            let before = config.app.len();
            config.app.retain(|a| a.name != name);
            if config.app.len() == before {
                return DaemonResponse {
                    success: false,
                    message: format!("App '{}' not found", name),
                };
            }
            if let Err(e) = config.save(None) {
                return DaemonResponse {
                    success: false,
                    message: format!("Failed to save config: {}", e),
                };
            }
            if let Err(e) = state.reload_config(config) {
                return DaemonResponse {
                    success: false,
                    message: format!("Failed to reload: {}", e),
                };
            }
            DaemonResponse {
                success: true,
                message: format!("Removed app '{}'", name),
            }
        }
        Command::Enable { name } => toggle_app(state, &name, true).await,
        Command::Disable { name } => toggle_app(state, &name, false).await,
        Command::Reload => match Config::load(None) {
            Ok(config) => {
                let mut state = state.lock().await;
                match state.reload_config(config) {
                    Ok(()) => DaemonResponse {
                        success: true,
                        message: "Config reloaded".into(),
                    },
                    Err(e) => DaemonResponse {
                        success: false,
                        message: format!("Reload failed: {}", e),
                    },
                }
            }
            Err(e) => DaemonResponse {
                success: false,
                message: format!("Failed to read config: {}", e),
            },
        },
        Command::Rules => {
            let state = state.lock().await;
            match state.nft().list_rules() {
                Ok(rules) => DaemonResponse {
                    success: true,
                    message: rules,
                },
                Err(e) => DaemonResponse {
                    success: false,
                    message: format!("Failed to list rules: {}", e),
                },
            }
        }
        Command::Daemon => DaemonResponse {
            success: false,
            message: "Cannot run daemon via IPC".into(),
        },
    }
}

async fn toggle_app(state: Arc<Mutex<AppState>>, name: &str, enable: bool) -> DaemonResponse {
    let mut state = state.lock().await;
    let mut config = state.config().clone();
    let found = config.app.iter_mut().find(|a| a.name == name);
    match found {
        Some(app) => {
            app.enabled = enable;
            if let Err(e) = config.save(None) {
                return DaemonResponse {
                    success: false,
                    message: format!("Failed to save config: {}", e),
                };
            }
            if let Err(e) = state.reload_config(config) {
                return DaemonResponse {
                    success: false,
                    message: format!("Failed to reload: {}", e),
                };
            }
            let action = if enable { "Enabled" } else { "Disabled" };
            DaemonResponse {
                success: true,
                message: format!("{} app '{}'", action, name),
            }
        }
        None => DaemonResponse {
            success: false,
            message: format!("App '{}' not found", name),
        },
    }
}

/// Send a command to the daemon via IPC (called by CLI)
pub async fn client_request(cmd: Command) -> Result<()> {
    let stream = UnixStream::connect(SOCKET_PATH).await.with_context(|| {
        format!(
            "Failed to connect to AFW daemon at {}. Is the daemon running?",
            SOCKET_PATH
        )
    })?;

    let (reader, mut writer) = stream.into_split();

    let cmd_json = serde_json::to_string(&cmd)?;
    writer.write_all(cmd_json.as_bytes()).await?;
    writer.write_all(b"\n").await?;
    writer.shutdown().await?;

    let mut reader = BufReader::new(reader);
    let mut response_line = String::new();
    reader.read_line(&mut response_line).await?;

    let response: DaemonResponse =
        serde_json::from_str(response_line.trim()).context("Failed to parse daemon response")?;

    if response.success {
        print!("{}", response.message);
    } else {
        eprintln!("Error: {}", response.message);
        std::process::exit(1);
    }

    Ok(())
}
