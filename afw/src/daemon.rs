use anyhow::{Context, Result};
use log::{debug, error, info, warn};
use std::sync::Arc;
use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::{mpsc, Mutex};

use afw_common::{EVENT_EXEC, EVENT_EXIT, PROTO_TCP, PROTO_UDP};

use crate::config::Config;
use crate::ebpf_loader;
use crate::ipc;
use crate::nft::{NftBackend, RealNftBackend};
use crate::state::AppState;

pub async fn run() -> Result<()> {
    eprintln!("{}", crate::banner::BANNER);
    info!("AFW daemon starting...");

    let config = Config::load(None).context("Failed to load configuration")?;
    info!(
        "Loaded config: {} base port rules, {} app rules",
        config.base.outbound.len(),
        config.app.len()
    );

    let nft = RealNftBackend;
    nft.init_table(
        &config.base.outbound,
        config.base.icmp,
        config.base.loopback,
    )
    .context("Failed to initialize nftables")?;

    let mut state = AppState::new(config.clone());
    state.scan_existing_processes()?;

    let state_arc = Arc::new(Mutex::new(state));

    // Channels for eBPF events
    let (proc_tx, mut proc_rx) = mpsc::unbounded_channel();
    let (conn_tx, mut conn_rx) = mpsc::unbounded_channel();

    let _bpf = ebpf_loader::load_and_attach(proc_tx, conn_tx)
        .await
        .context("Failed to load eBPF programs")?;
    info!("eBPF programs loaded and attached (process + connection tracking)");

    let ipc_state = Arc::clone(&state_arc);
    tokio::spawn(async move {
        if let Err(e) = ipc::start_server(ipc_state).await {
            error!("IPC server error: {}", e);
        }
    });

    let mut sigterm = signal(SignalKind::terminate())?;
    let mut sigint = signal(SignalKind::interrupt())?;

    info!("AFW daemon ready. Monitoring process and connection events...");

    // Periodic timer to check aggregation windows for unknown apps
    let mut aggregation_tick = tokio::time::interval(std::time::Duration::from_secs(2));

    loop {
        tokio::select! {
            Some(event) = proc_rx.recv() => {
                let comm = ebpf_loader::comm_to_string(&event.comm);
                let mut state = state_arc.lock().await;

                let result = match event.event_type {
                    EVENT_EXEC => state.handle_exec(event.pid, &comm),
                    EVENT_EXIT => state.handle_exit(event.pid, &comm),
                    _ => {
                        warn!("Unknown event type: {}", event.event_type);
                        Ok(())
                    }
                };

                if let Err(e) = result {
                    error!("Error handling event for '{}' (pid {}): {}", comm, event.pid, e);
                }
            }
            Some(conn) = conn_rx.recv() => {
                let comm = ebpf_loader::comm_to_string(&conn.comm);
                let dest_addr = ebpf_loader::ipv4_to_string(conn.dest_addr);
                let protocol = match conn.protocol {
                    PROTO_TCP => "tcp",
                    PROTO_UDP => "udp",
                    _ => "unknown",
                };

                let mut state = state_arc.lock().await;
                state.handle_connection(
                    &comm,
                    conn.dest_port,
                    protocol,
                    &dest_addr,
                );
            }
            _ = aggregation_tick.tick() => {
                let mut state = state_arc.lock().await;
                let summaries = state.check_aggregation_windows();
                for summary in summaries {
                    info!(
                        "BLOCKED: '{}' tried {} port(s): {} ({} attempts, {} destination(s))",
                        summary.binary,
                        summary.ports.len(),
                        summary.ports.iter()
                            .map(|(p, proto)| format!("{}/{}", p, proto))
                            .collect::<Vec<_>>()
                            .join(", "),
                        summary.attempt_count,
                        summary.dest_addrs.len(),
                    );
                    info!("  To allow: {}", summary.suggested_command());

                    // Spawn notification in background so action buttons
                    // don't block the daemon event loop
                    let state_clone = Arc::clone(&state_arc);
                    let binary = summary.binary.clone();
                    tokio::spawn(async move {
                        // This runs on a blocking thread since notify-send --wait blocks
                        let action = tokio::task::spawn_blocking(move || {
                            let mut n = crate::notify::Notifier::new();
                            n.notify_blocked_app(&summary)
                        })
                        .await;

                        if let Ok(Some(action)) = action {
                            use crate::notify::NotifyAction;
                            let mut state = state_clone.lock().await;
                            match action {
                                NotifyAction::Approve => {
                                    info!("User approved '{}' via notification", binary);
                                    // Build config and save
                                    if let Some(conn) = state.unknown_connections().get(&binary).cloned() {
                                        let port_rules: Vec<crate::config::PortRule> = conn.ports.iter().map(|(port, proto)| {
                                            crate::config::PortRule { port: *port, range_end: None, protocol: proto.clone() }
                                        }).collect();
                                        let app_name = binary.to_lowercase().replace(' ', "-");
                                        // Validate names before using in nft rules / config
                                        if let Err(e) = crate::config::validate_name(&app_name) {
                                            error!("Invalid app name '{}': {}", app_name, e);
                                            return;
                                        }
                                        if let Err(e) = crate::config::validate_name(&binary) {
                                            error!("Invalid binary name '{}': {}", binary, e);
                                            return;
                                        }
                                        let mut cfg = state.config().clone();
                                        cfg.app.push(crate::config::AppConfig {
                                            name: app_name.clone(),
                                            binary: binary.clone(),
                                            enabled: true,
                                            outbound: port_rules,
                                        });
                                        if let Err(e) = cfg.save(None) {
                                            error!("Failed to save config for '{}': {}", binary, e);
                                        } else if let Err(e) = state.reload_config(cfg) {
                                            error!("Failed to reload after approving '{}': {}", binary, e);
                                        } else {
                                            state.clear_unknown(&binary);
                                            info!("Permanently approved '{}'", app_name);
                                        }
                                    }
                                }
                                NotifyAction::AllowOnce => {
                                    info!("User allowed '{}' once via notification", binary);
                                    if let Err(e) = state.allow_once(&binary) {
                                        error!("Failed to allow-once '{}': {}", binary, e);
                                    }
                                }
                                NotifyAction::Deny => {
                                    info!("User denied '{}' via notification", binary);
                                    state.deny_app(&binary);
                                }
                                NotifyAction::Dismissed => {
                                    debug!("Notification for '{}' dismissed", binary);
                                }
                            }
                        }
                    });
                }
                // Drop the lock so spawned tasks can acquire it
                drop(state);
            }
            _ = sigterm.recv() => {
                info!("Received SIGTERM, shutting down...");
                break;
            }
            _ = sigint.recv() => {
                info!("Received SIGINT, shutting down...");
                break;
            }
        }
    }

    info!("Cleaning up nftables rules...");
    if let Err(e) = nft.cleanup() {
        warn!(
            "Failed to cleanup nftables: {}. The ExecStopPost should handle it.",
            e
        );
    }

    info!("AFW daemon stopped");
    Ok(())
}
