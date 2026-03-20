#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{bpf_get_current_pid_tgid, bpf_probe_read_user},
    macros::{kprobe, map, tracepoint},
    maps::PerfEventArray,
    programs::{ProbeContext, TracePointContext},
};

use afw_common::{ConnectionEvent, ProcessEvent, EVENT_EXEC, EVENT_EXIT, PROTO_TCP};

#[map]
static EVENTS: PerfEventArray<ProcessEvent> = PerfEventArray::new(0);

#[map]
static CONN_EVENTS: PerfEventArray<ConnectionEvent> = PerfEventArray::new(0);

/// Read the comm field from the current task
unsafe fn read_comm() -> [u8; 16] {
    let mut comm = [0u8; 16];
    let ret = aya_ebpf::helpers::bpf_get_current_comm();
    match ret {
        Ok(c) => comm = c,
        Err(_) => {}
    }
    comm
}

// === Process exec/exit tracepoints ===

#[tracepoint]
pub fn trace_exec(ctx: TracePointContext) -> u32 {
    match try_trace_exec(&ctx) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

fn try_trace_exec(ctx: &TracePointContext) -> Result<(), i64> {
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let comm = unsafe { read_comm() };

    let event = ProcessEvent {
        pid,
        event_type: EVENT_EXEC,
        comm,
    };

    EVENTS.output(ctx, &event, 0);
    Ok(())
}

#[tracepoint]
pub fn trace_exit(ctx: TracePointContext) -> u32 {
    match try_trace_exit(&ctx) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

fn try_trace_exit(ctx: &TracePointContext) -> Result<(), i64> {
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let comm = unsafe { read_comm() };

    let event = ProcessEvent {
        pid,
        event_type: EVENT_EXIT,
        comm,
    };

    EVENTS.output(ctx, &event, 0);
    Ok(())
}

// === Connection tracking kprobe ===
//
// Hooks tcp_v4_connect(struct sock *sk, struct sockaddr *uaddr, int addr_len)
// to capture outbound TCP connection attempts.
//
// sockaddr_in layout:
//   offset 0: sa_family (u16) — AF_INET = 2
//   offset 2: sin_port  (u16) — network byte order
//   offset 4: sin_addr  (u32) — network byte order

#[kprobe]
pub fn trace_connect(ctx: ProbeContext) -> u32 {
    match try_trace_connect(&ctx) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

fn try_trace_connect(ctx: &ProbeContext) -> Result<(), i64> {
    // Second argument: struct sockaddr *uaddr
    let sockaddr_ptr: *const u8 = ctx.arg(1).ok_or(1)?;

    // Read sa_family (offset 0, 2 bytes)
    let family: u16 =
        unsafe { bpf_probe_read_user(sockaddr_ptr as *const u16).map_err(|_| 1)? };

    // Only handle AF_INET (IPv4) for now
    if family != 2 {
        return Ok(());
    }

    // Read sin_port (offset 2, network byte order)
    let port_be: u16 =
        unsafe { bpf_probe_read_user(sockaddr_ptr.wrapping_add(2) as *const u16).map_err(|_| 1)? };
    let port = u16::from_be(port_be);

    // Skip port 0 (not a real connection)
    if port == 0 {
        return Ok(());
    }

    // Read sin_addr (offset 4, network byte order)
    let addr: u32 =
        unsafe { bpf_probe_read_user(sockaddr_ptr.wrapping_add(4) as *const u32).map_err(|_| 1)? };

    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let comm = unsafe { read_comm() };

    let event = ConnectionEvent {
        pid,
        dest_port: port,
        protocol: PROTO_TCP,
        _pad: 0,
        dest_addr: addr,
        comm,
    };

    CONN_EVENTS.output(ctx, &event, 0);
    Ok(())
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
