use afw::cli::{Command, DaemonResponse};

// === Command serialization roundtrips (used by IPC) ===

#[test]
fn serialize_status_command() {
    let cmd = Command::Status;
    let json = serde_json::to_string(&cmd).unwrap();
    let deserialized: Command = serde_json::from_str(&json).unwrap();
    assert!(matches!(deserialized, Command::Status));
}

#[test]
fn serialize_list_command() {
    let cmd = Command::List;
    let json = serde_json::to_string(&cmd).unwrap();
    let deserialized: Command = serde_json::from_str(&json).unwrap();
    assert!(matches!(deserialized, Command::List));
}

#[test]
fn serialize_add_command() {
    let cmd = Command::Add {
        name: "test".into(),
        binary: "test_bin".into(),
        ports: vec!["443/tcp".into(), "80/tcp".into()],
    };
    let json = serde_json::to_string(&cmd).unwrap();
    let deserialized: Command = serde_json::from_str(&json).unwrap();
    match deserialized {
        Command::Add { name, binary, ports } => {
            assert_eq!(name, "test");
            assert_eq!(binary, "test_bin");
            assert_eq!(ports, vec!["443/tcp", "80/tcp"]);
        }
        _ => panic!("Expected Add command"),
    }
}

#[test]
fn serialize_remove_command() {
    let cmd = Command::Remove { name: "discord".into() };
    let json = serde_json::to_string(&cmd).unwrap();
    let deserialized: Command = serde_json::from_str(&json).unwrap();
    match deserialized {
        Command::Remove { name } => assert_eq!(name, "discord"),
        _ => panic!("Expected Remove command"),
    }
}

#[test]
fn serialize_enable_command() {
    let cmd = Command::Enable { name: "app".into() };
    let json = serde_json::to_string(&cmd).unwrap();
    let deserialized: Command = serde_json::from_str(&json).unwrap();
    match deserialized {
        Command::Enable { name } => assert_eq!(name, "app"),
        _ => panic!("Expected Enable command"),
    }
}

#[test]
fn serialize_disable_command() {
    let cmd = Command::Disable { name: "app".into() };
    let json = serde_json::to_string(&cmd).unwrap();
    let deserialized: Command = serde_json::from_str(&json).unwrap();
    match deserialized {
        Command::Disable { name } => assert_eq!(name, "app"),
        _ => panic!("Expected Disable command"),
    }
}

#[test]
fn serialize_reload_command() {
    let cmd = Command::Reload;
    let json = serde_json::to_string(&cmd).unwrap();
    let deserialized: Command = serde_json::from_str(&json).unwrap();
    assert!(matches!(deserialized, Command::Reload));
}

#[test]
fn serialize_rules_command() {
    let cmd = Command::Rules;
    let json = serde_json::to_string(&cmd).unwrap();
    let deserialized: Command = serde_json::from_str(&json).unwrap();
    assert!(matches!(deserialized, Command::Rules));
}

#[test]
fn serialize_daemon_command() {
    let cmd = Command::Daemon;
    let json = serde_json::to_string(&cmd).unwrap();
    let deserialized: Command = serde_json::from_str(&json).unwrap();
    assert!(matches!(deserialized, Command::Daemon));
}

// === DaemonResponse ===

#[test]
fn daemon_response_success_roundtrip() {
    let resp = DaemonResponse {
        success: true,
        message: "All good".into(),
    };
    let json = serde_json::to_string(&resp).unwrap();
    let deserialized: DaemonResponse = serde_json::from_str(&json).unwrap();
    assert!(deserialized.success);
    assert_eq!(deserialized.message, "All good");
}

#[test]
fn daemon_response_failure_roundtrip() {
    let resp = DaemonResponse {
        success: false,
        message: "Something broke".into(),
    };
    let json = serde_json::to_string(&resp).unwrap();
    let deserialized: DaemonResponse = serde_json::from_str(&json).unwrap();
    assert!(!deserialized.success);
    assert_eq!(deserialized.message, "Something broke");
}

#[test]
fn daemon_response_empty_message() {
    let resp = DaemonResponse {
        success: true,
        message: String::new(),
    };
    let json = serde_json::to_string(&resp).unwrap();
    let deserialized: DaemonResponse = serde_json::from_str(&json).unwrap();
    assert!(deserialized.message.is_empty());
}

#[test]
fn daemon_response_with_special_chars() {
    let resp = DaemonResponse {
        success: true,
        message: "Line 1\nLine 2\n  → 443/tcp".into(),
    };
    let json = serde_json::to_string(&resp).unwrap();
    let deserialized: DaemonResponse = serde_json::from_str(&json).unwrap();
    assert!(deserialized.message.contains("→"));
    assert!(deserialized.message.contains('\n'));
}

#[test]
fn command_deserialize_invalid_json() {
    let result = serde_json::from_str::<Command>("not json");
    assert!(result.is_err());
}

#[test]
fn command_deserialize_unknown_variant() {
    let result = serde_json::from_str::<Command>(r#""Unknown""#);
    assert!(result.is_err());
}

// === Add command edge cases ===

#[test]
fn serialize_add_command_single_port() {
    let cmd = Command::Add {
        name: "minimal".into(),
        binary: "bin".into(),
        ports: vec!["22/tcp".into()],
    };
    let json = serde_json::to_string(&cmd).unwrap();
    let deserialized: Command = serde_json::from_str(&json).unwrap();
    match deserialized {
        Command::Add { ports, .. } => assert_eq!(ports.len(), 1),
        _ => panic!("Expected Add"),
    }
}

#[test]
fn serialize_add_command_with_ranges() {
    let cmd = Command::Add {
        name: "game".into(),
        binary: "game_bin".into(),
        ports: vec!["27000-27050/udp".into(), "443/tcp".into()],
    };
    let json = serde_json::to_string(&cmd).unwrap();
    assert!(json.contains("27000-27050/udp"));
}
