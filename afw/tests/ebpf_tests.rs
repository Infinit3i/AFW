use afw::ebpf_loader::comm_to_string;
use afw_common::{ProcessEvent, EVENT_EXEC, EVENT_EXIT};

fn make_comm(s: &str) -> [u8; 16] {
    let mut comm = [0u8; 16];
    let bytes = s.as_bytes();
    let len = bytes.len().min(16);
    comm[..len].copy_from_slice(&bytes[..len]);
    comm
}

// === comm_to_string ===

#[test]
fn comm_normal_name() {
    assert_eq!(comm_to_string(&make_comm("firefox")), "firefox");
}

#[test]
fn comm_empty() {
    assert_eq!(comm_to_string(&[0u8; 16]), "");
}

#[test]
fn comm_full_16_chars() {
    let comm = [b'a'; 16];
    assert_eq!(comm_to_string(&comm), "aaaaaaaaaaaaaaaa");
    assert_eq!(comm_to_string(&comm).len(), 16);
}

#[test]
fn comm_with_null_in_middle() {
    let mut comm = make_comm("test");
    comm[5] = b'x'; // after the null at index 4
    assert_eq!(comm_to_string(&comm), "test");
}

#[test]
fn comm_single_char() {
    assert_eq!(comm_to_string(&make_comm("a")), "a");
}

#[test]
fn comm_15_chars() {
    assert_eq!(
        comm_to_string(&make_comm("123456789012345")),
        "123456789012345"
    );
}

#[test]
fn comm_with_dash() {
    assert_eq!(comm_to_string(&make_comm("afw-ebpf")), "afw-ebpf");
}

#[test]
fn comm_with_underscore() {
    assert_eq!(comm_to_string(&make_comm("my_daemon")), "my_daemon");
}

// === ProcessEvent struct ===

#[test]
fn event_constants() {
    assert_eq!(EVENT_EXEC, 0);
    assert_eq!(EVENT_EXIT, 1);
    assert_ne!(EVENT_EXEC, EVENT_EXIT);
}

#[test]
fn process_event_create_exec() {
    let event = ProcessEvent {
        pid: 1234,
        event_type: EVENT_EXEC,
        comm: make_comm("firefox"),
    };
    assert_eq!(event.pid, 1234);
    assert_eq!(event.event_type, EVENT_EXEC);
    assert_eq!(comm_to_string(&event.comm), "firefox");
}

#[test]
fn process_event_create_exit() {
    let event = ProcessEvent {
        pid: 5678,
        event_type: EVENT_EXIT,
        comm: make_comm("steam"),
    };
    assert_eq!(event.pid, 5678);
    assert_eq!(event.event_type, EVENT_EXIT);
}

#[test]
fn process_event_is_copy() {
    let event = ProcessEvent {
        pid: 100,
        event_type: EVENT_EXEC,
        comm: make_comm("test"),
    };
    let copy = event; // Copy
    assert_eq!(event.pid, copy.pid); // original still usable
}

#[test]
fn comm_with_non_utf8_bytes() {
    let mut comm = [0u8; 16];
    comm[0] = 0xFF;
    comm[1] = 0xFE;
    comm[2] = 0;
    let result = comm_to_string(&comm);
    // Should not panic, uses lossy conversion
    assert!(!result.is_empty());
}

#[test]
fn process_event_size() {
    // ProcessEvent is repr(C): u32 + u32 + [u8;16] = 24 bytes
    assert_eq!(std::mem::size_of::<ProcessEvent>(), 24);
}

#[test]
fn process_event_alignment() {
    // repr(C) with u32 fields means 4-byte alignment
    assert_eq!(std::mem::align_of::<ProcessEvent>(), 4);
}

#[test]
fn process_event_clone() {
    let event = ProcessEvent {
        pid: 200,
        event_type: EVENT_EXIT,
        comm: make_comm("app"),
    };
    let cloned = event.clone();
    assert_eq!(cloned.pid, event.pid);
    assert_eq!(cloned.event_type, event.event_type);
}

// === comm with various byte values ===

#[test]
fn comm_all_printable_ascii() {
    // Fill with printable ASCII chars (space=32 through tilde=126, take 16)
    let mut comm = [0u8; 16];
    for i in 0..16 {
        comm[i] = (b'A' + i as u8) % 127; // A,B,C,...,P
    }
    let result = comm_to_string(&comm);
    assert_eq!(result.len(), 16);
    assert_eq!(result.as_bytes()[0], b'A');
}

#[test]
fn comm_with_high_bytes_no_null() {
    // All non-zero bytes, including > 127
    let mut comm = [0u8; 16];
    for i in 0..16 {
        comm[i] = 128 + i as u8;
    }
    let result = comm_to_string(&comm);
    // Should not panic, uses lossy UTF-8 conversion
    assert_eq!(result.len() > 0, true);
}

#[test]
fn comm_with_only_null_bytes() {
    let comm = [0u8; 16];
    assert_eq!(comm_to_string(&comm), "");
}

#[test]
fn comm_first_byte_null() {
    let mut comm = [0u8; 16];
    comm[1] = b'a'; // data after null
                    // Should return empty since first byte is null
    assert_eq!(comm_to_string(&comm), "");
}

#[test]
fn comm_all_same_nonzero_byte() {
    let comm = [b'z'; 16];
    assert_eq!(comm_to_string(&comm), "zzzzzzzzzzzzzzzz");
}

#[test]
fn comm_with_space() {
    assert_eq!(comm_to_string(&make_comm("my app")), "my app");
}

#[test]
fn comm_with_dot() {
    assert_eq!(comm_to_string(&make_comm("node.js")), "node.js");
}

#[test]
fn comm_with_numbers() {
    assert_eq!(comm_to_string(&make_comm("python3.11")), "python3.11");
}

#[test]
fn comm_exactly_16_bytes_various() {
    let comm = *b"0123456789abcdef";
    assert_eq!(comm_to_string(&comm), "0123456789abcdef");
}

#[test]
fn comm_14_chars_then_null() {
    let mut comm = [0u8; 16];
    for i in 0..14 {
        comm[i] = b'X';
    }
    assert_eq!(comm_to_string(&comm), "XXXXXXXXXXXXXX");
    assert_eq!(comm_to_string(&comm).len(), 14);
}

// === ProcessEvent field offsets ===

#[test]
fn process_event_field_offset_pid() {
    // In repr(C): pid is at offset 0
    let offset = std::mem::offset_of!(ProcessEvent, pid);
    assert_eq!(offset, 0);
}

#[test]
fn process_event_field_offset_event_type() {
    // event_type is after pid (u32), so offset 4
    let offset = std::mem::offset_of!(ProcessEvent, event_type);
    assert_eq!(offset, 4);
}

#[test]
fn process_event_field_offset_comm() {
    // comm is after pid (u32) + event_type (u32), so offset 8
    let offset = std::mem::offset_of!(ProcessEvent, comm);
    assert_eq!(offset, 8);
}

// === ProcessEvent with extreme values ===

#[test]
fn process_event_max_pid() {
    let event = ProcessEvent {
        pid: u32::MAX,
        event_type: EVENT_EXEC,
        comm: make_comm("max_pid"),
    };
    assert_eq!(event.pid, u32::MAX);
}

#[test]
fn process_event_zero_pid() {
    let event = ProcessEvent {
        pid: 0,
        event_type: EVENT_EXIT,
        comm: make_comm("zero"),
    };
    assert_eq!(event.pid, 0);
}

#[test]
fn process_event_unknown_event_type() {
    // Event types beyond EXEC/EXIT are technically possible from eBPF
    let event = ProcessEvent {
        pid: 100,
        event_type: 99,
        comm: make_comm("weird"),
    };
    assert_eq!(event.event_type, 99);
    assert_ne!(event.event_type, EVENT_EXEC);
    assert_ne!(event.event_type, EVENT_EXIT);
}

#[test]
fn process_event_max_event_type() {
    let event = ProcessEvent {
        pid: 1,
        event_type: u32::MAX,
        comm: [0xFF; 16],
    };
    assert_eq!(event.event_type, u32::MAX);
}

// === Byte-level representation ===

#[test]
fn process_event_as_bytes_roundtrip() {
    let original = ProcessEvent {
        pid: 42,
        event_type: EVENT_EXEC,
        comm: make_comm("test"),
    };
    // Simulate what eBPF perf buffer does: write bytes, read back
    let bytes: [u8; 24] = unsafe { std::mem::transmute(original) };
    let recovered: ProcessEvent = unsafe { std::mem::transmute(bytes) };
    assert_eq!(recovered.pid, 42);
    assert_eq!(recovered.event_type, EVENT_EXEC);
    assert_eq!(comm_to_string(&recovered.comm), "test");
}

#[test]
fn process_event_default_comm_is_zeroed() {
    let event = ProcessEvent {
        pid: 1,
        event_type: EVENT_EXEC,
        comm: [0u8; 16],
    };
    assert_eq!(comm_to_string(&event.comm), "");
}

// === Real-world Linux process comm names ===

#[test]
fn comm_real_world_process_names() {
    let names = [
        "systemd",
        "sshd",
        "bash",
        "zsh",
        "init",
        "cron",
        "Xwayland",
        "pipewire",
        "dbus-broker",
        "Discord",
        "firefox",
        "steam",
        "code-oss",
        "signal-deskto",
        "systemd-resolve",
        "wg-quick",
    ];
    for name in names {
        let result = comm_to_string(&make_comm(name));
        assert_eq!(result, name, "Failed roundtrip for: {}", name);
    }
}

#[test]
fn comm_truncated_at_16_chars() {
    // Linux kernel truncates comm to 16 bytes (TASK_COMM_LEN)
    // "signal-desktop" is 15 chars, fits. "systemd-resolved" is 16, fits exactly.
    let long_name = "systemd-resolved"; // exactly 16 chars
    assert_eq!(long_name.len(), 16);
    let comm = make_comm(long_name);
    assert_eq!(comm_to_string(&comm), long_name);
}

#[test]
fn comm_longer_than_16_gets_truncated() {
    // Simulating what the kernel does — truncates at 16
    let long_name = "very-long-process-name-here";
    let comm = make_comm(long_name); // make_comm caps at 16
    assert_eq!(comm_to_string(&comm), &long_name[..16]);
}

// === ProcessEvent copy semantics (important for eBPF perf buffer) ===

#[test]
fn process_event_copy_independent() {
    let event1 = ProcessEvent {
        pid: 100,
        event_type: EVENT_EXEC,
        comm: make_comm("app"),
    };
    let mut event2 = event1; // Copy
    event2.pid = 200;
    event2.event_type = EVENT_EXIT;
    // event1 unchanged
    assert_eq!(event1.pid, 100);
    assert_eq!(event1.event_type, EVENT_EXEC);
    assert_eq!(event2.pid, 200);
    assert_eq!(event2.event_type, EVENT_EXIT);
}

#[test]
fn process_event_ptr_read_unaligned_simulation() {
    // This is how the daemon reads events from the perf buffer
    let event = ProcessEvent {
        pid: 12345,
        event_type: EVENT_EXIT,
        comm: make_comm("firefox"),
    };
    let bytes = unsafe {
        std::slice::from_raw_parts(
            &event as *const ProcessEvent as *const u8,
            std::mem::size_of::<ProcessEvent>(),
        )
    };
    let recovered: ProcessEvent =
        unsafe { std::ptr::read_unaligned(bytes.as_ptr() as *const ProcessEvent) };
    assert_eq!(recovered.pid, 12345);
    assert_eq!(recovered.event_type, EVENT_EXIT);
    assert_eq!(comm_to_string(&recovered.comm), "firefox");
}
