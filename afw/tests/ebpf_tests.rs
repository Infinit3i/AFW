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
    assert_eq!(comm_to_string(&make_comm("123456789012345")), "123456789012345");
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
