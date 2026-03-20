use anyhow::{Context, Result};
use log::{error, info, warn};
use std::sync::Arc;
use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::{mpsc, Mutex};

use afw_common::{EVENT_EXEC, EVENT_EXIT};

use crate::config::Config;
use crate::ebpf_loader;
use crate::ipc;
use crate::nft::{NftBackend, RealNftBackend};
use crate::state::AppState;

pub async fn run() -> Result<()> {
    info!("AFW daemon starting...");

    let config = Config::load(None).context("Failed to load configuration")?;
    info!(
        "Loaded config: {} base port rules, {} app rules",
        config.base.outbound.len(),
        config.app.len()
    );

    let nft = RealNftBackend;
    nft.init_table(&config.base.outbound, config.base.icmp, config.base.loopback)
        .context("Failed to initialize nftables")?;

    let mut state = AppState::new(config.clone());
    state.scan_existing_processes()?;

    let state = Arc::new(Mutex::new(state));

    let (tx, mut rx) = mpsc::unbounded_channel();

    let _bpf = ebpf_loader::load_and_attach(tx)
        .await
        .context("Failed to load eBPF programs")?;
    info!("eBPF programs loaded and attached");

    let ipc_state = Arc::clone(&state);
    tokio::spawn(async move {
        if let Err(e) = ipc::start_server(ipc_state).await {
            error!("IPC server error: {}", e);
        }
    });

    let mut sigterm = signal(SignalKind::terminate())?;
    let mut sigint = signal(SignalKind::interrupt())?;

    info!("AFW daemon ready. Monitoring process events...");

    loop {
        tokio::select! {
            Some(event) = rx.recv() => {
                let comm = ebpf_loader::comm_to_string(&event.comm);
                let mut state = state.lock().await;

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
        warn!("Failed to cleanup nftables: {}. The ExecStopPost should handle it.", e);
    }

    info!("AFW daemon stopped");
    Ok(())
}
