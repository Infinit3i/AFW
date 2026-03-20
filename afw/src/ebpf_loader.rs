use anyhow::{Context, Result};
use aya::maps::AsyncPerfEventArray;
use aya::programs::{KProbe, TracePoint};
use aya::util::online_cpus;
use aya::{Ebpf, EbpfLoader};
use bytes::BytesMut;
use log::{error, info};
use tokio::sync::mpsc;

use afw_common::{ConnectionEvent, ProcessEvent};

/// Path to the compiled eBPF object file
fn ebpf_obj_path() -> &'static str {
    concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../target/bpfel-unknown-none/release/afw-ebpf"
    )
}

/// Load and attach eBPF programs for process and connection tracking
pub async fn load_and_attach(
    proc_tx: mpsc::UnboundedSender<ProcessEvent>,
    conn_tx: mpsc::UnboundedSender<ConnectionEvent>,
) -> Result<Ebpf> {
    let ebpf_path = ebpf_obj_path();
    let ebpf_bytes = std::fs::read(ebpf_path).with_context(|| {
        format!(
            "Failed to read eBPF object at {}. Did you run 'cargo xtask build-ebpf --release'?",
            ebpf_path
        )
    })?;

    let mut bpf = EbpfLoader::new()
        .load(&ebpf_bytes)
        .context("Failed to load eBPF programs")?;

    // Attach process exec tracepoint
    let exec_prog: &mut TracePoint = bpf
        .program_mut("trace_exec")
        .context("trace_exec program not found")?
        .try_into()?;
    exec_prog.load()?;
    exec_prog
        .attach("sched", "sched_process_exec")
        .context("Failed to attach trace_exec")?;
    info!("Attached eBPF tracepoint: sched/sched_process_exec");

    // Attach process exit tracepoint
    let exit_prog: &mut TracePoint = bpf
        .program_mut("trace_exit")
        .context("trace_exit program not found")?
        .try_into()?;
    exit_prog.load()?;
    exit_prog
        .attach("sched", "sched_process_exit")
        .context("Failed to attach trace_exit")?;
    info!("Attached eBPF tracepoint: sched/sched_process_exit");

    // Attach connection tracking kprobe
    let connect_prog: &mut KProbe = bpf
        .program_mut("trace_connect")
        .context("trace_connect program not found")?
        .try_into()?;
    connect_prog.load()?;
    connect_prog
        .attach("tcp_v4_connect", 0)
        .context("Failed to attach trace_connect kprobe")?;
    info!("Attached eBPF kprobe: tcp_v4_connect");

    // Set up perf event reading for process events
    let mut proc_perf =
        AsyncPerfEventArray::try_from(bpf.take_map("EVENTS").context("EVENTS map not found")?)?;

    let cpus = online_cpus().map_err(|(msg, e)| anyhow::anyhow!("{}: {}", msg, e))?;
    for &cpu_id in &cpus {
        let mut buf = proc_perf.open(cpu_id, None)?;
        let tx = proc_tx.clone();

        tokio::spawn(async move {
            let mut buffers = (0..10)
                .map(|_| BytesMut::with_capacity(std::mem::size_of::<ProcessEvent>()))
                .collect::<Vec<_>>();

            loop {
                let events = match buf.read_events(&mut buffers).await {
                    Ok(events) => events,
                    Err(e) => {
                        error!("Error reading process perf events on CPU {}: {}", cpu_id, e);
                        continue;
                    }
                };

                for buf in buffers.iter().take(events.read) {
                    if buf.len() >= std::mem::size_of::<ProcessEvent>() {
                        let event: ProcessEvent = unsafe {
                            std::ptr::read_unaligned(buf.as_ptr() as *const ProcessEvent)
                        };
                        if tx.send(event).is_err() {
                            return;
                        }
                    }
                }
            }
        });
    }

    // Set up perf event reading for connection events
    let mut conn_perf = AsyncPerfEventArray::try_from(
        bpf.take_map("CONN_EVENTS")
            .context("CONN_EVENTS map not found")?,
    )?;

    for &cpu_id in &cpus {
        let mut buf = conn_perf.open(cpu_id, None)?;
        let tx = conn_tx.clone();

        tokio::spawn(async move {
            let mut buffers = (0..10)
                .map(|_| BytesMut::with_capacity(std::mem::size_of::<ConnectionEvent>()))
                .collect::<Vec<_>>();

            loop {
                let events = match buf.read_events(&mut buffers).await {
                    Ok(events) => events,
                    Err(e) => {
                        error!(
                            "Error reading connection perf events on CPU {}: {}",
                            cpu_id, e
                        );
                        continue;
                    }
                };

                for buf in buffers.iter().take(events.read) {
                    if buf.len() >= std::mem::size_of::<ConnectionEvent>() {
                        let event: ConnectionEvent = unsafe {
                            std::ptr::read_unaligned(buf.as_ptr() as *const ConnectionEvent)
                        };
                        if tx.send(event).is_err() {
                            return;
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

/// Format an IPv4 address from network byte order u32
pub fn ipv4_to_string(addr: u32) -> String {
    let bytes = addr.to_be_bytes();
    format!("{}.{}.{}.{}", bytes[0], bytes[1], bytes[2], bytes[3])
}
