#![cfg_attr(not(feature = "user"), no_std)]

/// Event type constants
pub const EVENT_EXEC: u32 = 0;
pub const EVENT_EXIT: u32 = 1;

/// Process event sent from eBPF to userspace via perf buffer
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ProcessEvent {
    /// Process ID
    pub pid: u32,
    /// Event type: 0 = exec, 1 = exit
    pub event_type: u32,
    /// Process comm name (TASK_COMM_LEN = 16)
    pub comm: [u8; 16],
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for ProcessEvent {}
