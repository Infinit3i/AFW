#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::bpf_get_current_pid_tgid,
    macros::{map, tracepoint},
    maps::PerfEventArray,
    programs::TracePointContext,
};
use afw_common::{ProcessEvent, EVENT_EXEC, EVENT_EXIT};

#[map]
static EVENTS: PerfEventArray<ProcessEvent> = PerfEventArray::new(0);

/// Read the comm field from the current task
unsafe fn read_comm() -> [u8; 16] {
    let mut comm = [0u8; 16];
    let task = aya_ebpf::helpers::bpf_get_current_task() as *const u8;
    if !task.is_null() {
        // Read comm from task_struct - use bpf_get_current_comm helper
        let _ = aya_ebpf::helpers::bpf_get_current_comm();
    }
    // Use the bpf helper directly for comm
    let ret = aya_ebpf::helpers::bpf_get_current_comm();
    match ret {
        Ok(c) => comm = c,
        Err(_) => {}
    }
    comm
}

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

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
