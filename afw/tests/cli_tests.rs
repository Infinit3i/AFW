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

// === Add command with empty ports vec ===

#[test]
fn serialize_add_command_empty_ports() {
    let cmd = Command::Add {
        name: "bare_app".into(),
        binary: "bare".into(),
        ports: vec![],
    };
    let json = serde_json::to_string(&cmd).unwrap();
    let deserialized: Command = serde_json::from_str(&json).unwrap();
    match deserialized {
        Command::Add { name, binary, ports } => {
            assert_eq!(name, "bare_app");
            assert_eq!(binary, "bare");
            assert!(ports.is_empty());
        }
        _ => panic!("Expected Add"),
    }
}

// === Commands with special characters in names ===

#[test]
fn serialize_add_command_special_chars_in_name() {
    let cmd = Command::Add {
        name: "my-app_v2.0".into(),
        binary: "my-app_v2.0".into(),
        ports: vec!["443/tcp".into()],
    };
    let json = serde_json::to_string(&cmd).unwrap();
    let deserialized: Command = serde_json::from_str(&json).unwrap();
    match deserialized {
        Command::Add { name, binary, .. } => {
            assert_eq!(name, "my-app_v2.0");
            assert_eq!(binary, "my-app_v2.0");
        }
        _ => panic!("Expected Add"),
    }
}

#[test]
fn serialize_add_command_unicode_name() {
    let cmd = Command::Add {
        name: "app_\u{00e9}\u{00e8}".into(),
        binary: "bin_unicode".into(),
        ports: vec!["80/tcp".into()],
    };
    let json = serde_json::to_string(&cmd).unwrap();
    let deserialized: Command = serde_json::from_str(&json).unwrap();
    match deserialized {
        Command::Add { name, .. } => assert_eq!(name, "app_\u{00e9}\u{00e8}"),
        _ => panic!("Expected Add"),
    }
}

#[test]
fn serialize_remove_command_with_dashes() {
    let cmd = Command::Remove { name: "my-complex-app-name".into() };
    let json = serde_json::to_string(&cmd).unwrap();
    let deserialized: Command = serde_json::from_str(&json).unwrap();
    match deserialized {
        Command::Remove { name } => assert_eq!(name, "my-complex-app-name"),
        _ => panic!("Expected Remove"),
    }
}

#[test]
fn serialize_enable_command_with_dots() {
    let cmd = Command::Enable { name: "app.v2.3".into() };
    let json = serde_json::to_string(&cmd).unwrap();
    let deserialized: Command = serde_json::from_str(&json).unwrap();
    match deserialized {
        Command::Enable { name } => assert_eq!(name, "app.v2.3"),
        _ => panic!("Expected Enable"),
    }
}

#[test]
fn serialize_disable_command_with_underscores() {
    let cmd = Command::Disable { name: "my_app_name".into() };
    let json = serde_json::to_string(&cmd).unwrap();
    let deserialized: Command = serde_json::from_str(&json).unwrap();
    match deserialized {
        Command::Disable { name } => assert_eq!(name, "my_app_name"),
        _ => panic!("Expected Disable"),
    }
}

// === Add command with many ports ===

#[test]
fn serialize_add_command_many_ports() {
    let ports: Vec<String> = (1..=20).map(|i| format!("{}/tcp", 1000 + i)).collect();
    let cmd = Command::Add {
        name: "multi_port_app".into(),
        binary: "mpa".into(),
        ports: ports.clone(),
    };
    let json = serde_json::to_string(&cmd).unwrap();
    let deserialized: Command = serde_json::from_str(&json).unwrap();
    match deserialized {
        Command::Add { ports: deser_ports, .. } => {
            assert_eq!(deser_ports.len(), 20);
            assert_eq!(deser_ports[0], "1001/tcp");
            assert_eq!(deser_ports[19], "1020/tcp");
        }
        _ => panic!("Expected Add"),
    }
}

// === DaemonResponse edge cases ===

#[test]
fn daemon_response_long_message() {
    let long_msg = "x".repeat(10_000);
    let resp = DaemonResponse {
        success: true,
        message: long_msg.clone(),
    };
    let json = serde_json::to_string(&resp).unwrap();
    let deserialized: DaemonResponse = serde_json::from_str(&json).unwrap();
    assert_eq!(deserialized.message.len(), 10_000);
}

#[test]
fn daemon_response_with_json_in_message() {
    let resp = DaemonResponse {
        success: true,
        message: r#"{"nested": "json", "value": 42}"#.into(),
    };
    let json = serde_json::to_string(&resp).unwrap();
    let deserialized: DaemonResponse = serde_json::from_str(&json).unwrap();
    assert!(deserialized.message.contains("nested"));
}

#[test]
fn daemon_response_with_quotes_in_message() {
    let resp = DaemonResponse {
        success: false,
        message: "App 'discord' already exists. Remove it first.".into(),
    };
    let json = serde_json::to_string(&resp).unwrap();
    let deserialized: DaemonResponse = serde_json::from_str(&json).unwrap();
    assert!(deserialized.message.contains("'discord'"));
}

#[test]
fn command_deserialize_empty_string() {
    let result = serde_json::from_str::<Command>("");
    assert!(result.is_err());
}

#[test]
fn command_deserialize_null() {
    let result = serde_json::from_str::<Command>("null");
    assert!(result.is_err());
}

#[test]
fn command_clone_add() {
    let cmd = Command::Add {
        name: "test".into(),
        binary: "bin".into(),
        ports: vec!["80/tcp".into()],
    };
    let cloned = cmd.clone();
    match cloned {
        Command::Add { name, binary, ports } => {
            assert_eq!(name, "test");
            assert_eq!(binary, "bin");
            assert_eq!(ports, vec!["80/tcp"]);
        }
        _ => panic!("Expected Add"),
    }
}

#[test]
fn command_debug_format() {
    let cmd = Command::Status;
    let debug_str = format!("{:?}", cmd);
    assert!(debug_str.contains("Status"));
}

#[test]
fn all_commands_json_are_distinct() {
    let commands = vec![
        serde_json::to_string(&Command::Status).unwrap(),
        serde_json::to_string(&Command::List).unwrap(),
        serde_json::to_string(&Command::Reload).unwrap(),
        serde_json::to_string(&Command::Rules).unwrap(),
        serde_json::to_string(&Command::Daemon).unwrap(),
    ];
    for i in 0..commands.len() {
        for j in (i + 1)..commands.len() {
            assert_ne!(commands[i], commands[j], "Commands at {} and {} should differ", i, j);
        }
    }
}
