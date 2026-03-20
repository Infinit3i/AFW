#![cfg_attr(not(feature = "user"), no_std)]

/// Event type constants
pub const EVENT_EXEC: u32 = 0;
pub const EVENT_EXIT: u32 = 1;

/// Protocol constants
pub const PROTO_TCP: u8 = 6;
pub const PROTO_UDP: u8 = 17;

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

/// Connection event sent from eBPF when a process attempts an outbound connection
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ConnectionEvent {
    /// Process ID
    pub pid: u32,
    /// Destination port (host byte order)
    pub dest_port: u16,
    /// Protocol: 6 = TCP, 17 = UDP
    pub protocol: u8,
    /// Padding for alignment
    pub _pad: u8,
    /// Destination IPv4 address (network byte order)
    pub dest_addr: u32,
    /// Process comm name (TASK_COMM_LEN = 16)
    pub comm: [u8; 16],
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for ProcessEvent {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for ConnectionEvent {}
