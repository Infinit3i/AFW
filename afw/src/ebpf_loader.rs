use anyhow::{Context, Result};
use aya::maps::AsyncPerfEventArray;
use aya::programs::TracePoint;
use aya::util::online_cpus;
use aya::{Ebpf, EbpfLoader};
use bytes::BytesMut;
use log::{error, info};
use tokio::sync::mpsc;

use afw_common::ProcessEvent;

/// Path to the compiled eBPF object file
/// In release builds this is embedded; for development we look for the file
fn ebpf_obj_path() -> &'static str {
    // The xtask build puts it here
    concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../target/bpfel-unknown-none/release/afw-ebpf"
    )
}

/// Load and attach eBPF programs, return a channel of ProcessEvents
pub async fn load_and_attach(
    tx: mpsc::UnboundedSender<ProcessEvent>,
) -> Result<Ebpf> {
    // Try release first, fall back to debug
    let ebpf_path = ebpf_obj_path();
    let ebpf_bytes = std::fs::read(ebpf_path)
        .with_context(|| {
            format!(
                "Failed to read eBPF object at {}. Did you run 'cargo xtask build-ebpf --release'?",
                ebpf_path
            )
        })?;

    let mut bpf = EbpfLoader::new()
        .load(&ebpf_bytes)
        .context("Failed to load eBPF programs")?;

    // Attach tracepoints
    let exec_prog: &mut TracePoint = bpf
        .program_mut("trace_exec")
        .context("trace_exec program not found")?
        .try_into()?;
    exec_prog.load()?;
    exec_prog
        .attach("sched", "sched_process_exec")
        .context("Failed to attach trace_exec")?;
    info!("Attached eBPF tracepoint: sched/sched_process_exec");

    let exit_prog: &mut TracePoint = bpf
        .program_mut("trace_exit")
        .context("trace_exit program not found")?
        .try_into()?;
    exit_prog.load()?;
    exit_prog
        .attach("sched", "sched_process_exit")
        .context("Failed to attach trace_exit")?;
    info!("Attached eBPF tracepoint: sched/sched_process_exit");

    // Set up perf event reading
    let mut perf_array = AsyncPerfEventArray::try_from(
        bpf.take_map("EVENTS").context("EVENTS map not found")?,
    )?;

    let cpus = online_cpus().map_err(|(msg, e)| anyhow::anyhow!("{}: {}", msg, e))?;
    for cpu_id in cpus {
        let mut buf = perf_array.open(cpu_id, None)?;
        let tx = tx.clone();

        tokio::spawn(async move {
            let mut buffers = (0..10)
                .map(|_| BytesMut::with_capacity(std::mem::size_of::<ProcessEvent>()))
                .collect::<Vec<_>>();

            loop {
                let events = match buf.read_events(&mut buffers).await {
                    Ok(events) => events,
                    Err(e) => {
                        error!("Error reading perf events on CPU {}: {}", cpu_id, e);
                        continue;
                    }
                };

                for i in 0..events.read {
                    let buf = &buffers[i];
                    if buf.len() >= std::mem::size_of::<ProcessEvent>() {
                        let event: ProcessEvent =
                            unsafe { std::ptr::read_unaligned(buf.as_ptr() as *const ProcessEvent) };
                        if tx.send(event).is_err() {
                            return; // Channel closed, daemon shutting down
                        }
                    }
                }
            }
        });
    }

    Ok(bpf)
}

/// Extract a clean string from the comm field
pub fn comm_to_string(comm: &[u8; 16]) -> String {
    let end = comm.iter().position(|&b| b == 0).unwrap_or(16);
    String::from_utf8_lossy(&comm[..end]).to_string()
}
