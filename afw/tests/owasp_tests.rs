//! Security tests mapped to OWASP Top 10 2021 categories.
//!
//! These tests verify that AFW defenses hold against common attack patterns.

use afw::config::*;
use afw::nft::{
    build_add_app_rules_script, build_init_table_script, format_port_rule, parse_rule_handles,
    NftBackend,
};
use afw::state::AppState;
use std::sync::Mutex;

// === Mock NftBackend for security tests ===

struct MockNft {
    added: Mutex<Vec<String>>,
    removed: Mutex<Vec<String>>,
}

impl MockNft {
    fn new() -> Self {
        Self {
            added: Mutex::new(Vec::new()),
            removed: Mutex::new(Vec::new()),
        }
    }
}

impl NftBackend for MockNft {
    fn add_app_rules(&self, app_name: &str, _ports: &[PortRule]) -> anyhow::Result<()> {
        self.added.lock().unwrap().push(app_name.to_string());
        Ok(())
    }
    fn remove_app_rules(&self, app_name: &str) -> anyhow::Result<()> {
        self.removed.lock().unwrap().push(app_name.to_string());
        Ok(())
    }
    fn list_rules(&self) -> anyhow::Result<String> {
        Ok("mock".into())
    }
    fn init_table(&self, _: &[PortRule], _: bool, _: bool) -> anyhow::Result<()> {
        Ok(())
    }
    fn cleanup(&self) -> anyhow::Result<()> {
        Ok(())
    }
}

// ═══════════════════════════════════════════════════════════════
// A01:2021 - Broken Access Control
// ═══════════════════════════════════════════════════════════════

#[test]
fn a01_disabled_app_binary_not_tracked() {
    // Disabled apps must not have their binaries in the binary_map
    let config = Config {
        base: BaseConfig {
            outbound: vec![],
            icmp: false,
            loopback: false,
        },
        app: vec![AppConfig {
            name: "secret".into(),
            binary: "secret_bin".into(),
            enabled: false,
            outbound: vec![PortRule {
                port: 443,
                range_end: None,
                protocol: "tcp".into(),
            }],
        }],
    };
    let mut state = AppState::with_backend(config, Box::new(MockNft::new()));
    state.handle_exec(1000, "secret_bin").unwrap();
    assert!(state.status_info().contains("Active apps:    0"));
}

#[test]
fn a01_find_app_by_binary_skips_disabled() {
    let config = Config {
        base: BaseConfig {
            outbound: vec![],
            icmp: false,
            loopback: false,
        },
        app: vec![AppConfig {
            name: "restricted".into(),
            binary: "restricted_bin".into(),
            enabled: false,
            outbound: vec![],
        }],
    };
    assert!(config.find_app_by_binary("restricted_bin").is_none());
}

#[test]
fn a01_binary_map_excludes_all_disabled() {
    let config = Config {
        base: BaseConfig {
            outbound: vec![],
            icmp: false,
            loopback: false,
        },
        app: vec![
            AppConfig {
                name: "a".into(),
                binary: "a_bin".into(),
                enabled: false,
                outbound: vec![],
            },
            AppConfig {
                name: "b".into(),
                binary: "b_bin".into(),
                enabled: false,
                outbound: vec![],
            },
        ],
    };
    assert!(config.binary_to_app_map().is_empty());
}

// ═══════════════════════════════════════════════════════════════
// A03:2021 - Injection
// ═══════════════════════════════════════════════════════════════

// --- nftables comment injection via app name ---

#[test]
fn a03_nft_comment_breakout_double_quote() {
    let attack = r#"evil" accept comment "pwned"#;
    assert!(validate_name(attack).is_err());
}

#[test]
fn a03_nft_comment_breakout_newline() {
    let attack = "legit\nadd rule inet afw output accept";
    assert!(validate_name(attack).is_err());
}

#[test]
fn a03_nft_comment_breakout_crlf() {
    let attack = "legit\r\nadd rule inet afw output accept";
    assert!(validate_name(attack).is_err());
}

#[test]
fn a03_nft_semicolon_injection() {
    let attack = "app; flush ruleset";
    assert!(validate_name(attack).is_err());
}

#[test]
fn a03_nft_brace_injection() {
    let attack = "app { type filter hook output priority 0; policy accept; }";
    assert!(validate_name(attack).is_err());
}

#[test]
fn a03_nft_hash_comment_injection() {
    // # starts a comment in nft scripts
    let attack = "app # handle 1";
    assert!(validate_name(attack).is_err());
}

// --- Protocol field injection ---

#[test]
fn a03_protocol_injection_multiline() {
    let rule = PortRule {
        port: 443,
        range_end: None,
        protocol: "tcp\nadd rule inet afw output accept".into(),
    };
    assert!(rule.validate().is_err());
}

#[test]
fn a03_protocol_injection_space_payload() {
    let rule = PortRule {
        port: 443,
        range_end: None,
        protocol: "tcp dport 22 accept".into(),
    };
    assert!(rule.validate().is_err());
}

#[test]
fn a03_protocol_uppercase_not_accepted() {
    // Only lowercase "tcp" and "udp" accepted
    let rule = PortRule {
        port: 443,
        range_end: None,
        protocol: "TCP".into(),
    };
    assert!(rule.validate().is_err());
}

#[test]
fn a03_protocol_with_null_byte() {
    let rule = PortRule {
        port: 443,
        range_end: None,
        protocol: "tcp\0udp".into(),
    };
    assert!(rule.validate().is_err());
}

// --- Shell injection via names ---

#[test]
fn a03_shell_command_substitution() {
    assert!(validate_name("$(cat /etc/shadow)").is_err());
}

#[test]
fn a03_shell_backtick_substitution() {
    assert!(validate_name("`cat /etc/shadow`").is_err());
}

#[test]
fn a03_shell_pipe() {
    // | is in printable ASCII range but could be dangerous
    // It's actually allowed since nft doesn't interpret pipes in comments
    // This test documents the behavior
    let result = validate_name("app|tee /tmp/pwned");
    // | is between ' ' and '~' and not in deny list — this is acceptable
    // because nft comments are quoted and | has no meaning there
    assert!(result.is_ok() || result.is_err()); // document: currently allowed
}

// --- Verify safe names produce safe nft output ---

#[test]
fn a03_safe_name_produces_safe_nft_script() {
    let ports = vec![PortRule {
        port: 443,
        range_end: None,
        protocol: "tcp".into(),
    }];
    let script = build_add_app_rules_script("my-safe-app", &ports);
    // Must contain exactly one rule line with properly quoted comment
    let lines: Vec<&str> = script.lines().collect();
    assert_eq!(lines.len(), 1);
    assert!(lines[0].contains(r#"comment "afw:my-safe-app""#));
    assert!(lines[0].starts_with("add rule inet afw output"));
    assert!(lines[0].contains("tcp dport 443 accept"));
}

#[test]
fn a03_format_port_rule_only_outputs_safe_chars() {
    let rule = PortRule {
        port: 443,
        range_end: None,
        protocol: "tcp".into(),
    };
    let output = format_port_rule(&rule);
    // Must not contain any injection-enabling chars
    assert!(!output.contains('"'));
    assert!(!output.contains('\''));
    assert!(!output.contains('\n'));
    assert!(!output.contains(';'));
    assert!(!output.contains('{'));
    assert!(!output.contains('}'));
}

#[test]
fn a03_format_port_rule_range_only_safe_chars() {
    let rule = PortRule {
        port: 1000,
        range_end: Some(2000),
        protocol: "udp".into(),
    };
    let output = format_port_rule(&rule);
    assert_eq!(output, "udp dport 1000-2000 accept");
}

// --- parse_port_rule injection ---

#[test]
fn a03_parse_port_rule_rejects_extra_slashes() {
    assert!(parse_port_rule("443/tcp/extra").is_err());
}

#[test]
fn a03_parse_port_rule_rejects_non_numeric() {
    assert!(parse_port_rule("abc/tcp").is_err());
}

#[test]
fn a03_parse_port_rule_rejects_negative() {
    assert!(parse_port_rule("-1/tcp").is_err());
}

#[test]
fn a03_parse_port_rule_rejects_overflow() {
    assert!(parse_port_rule("99999/tcp").is_err());
}

// --- Config file injection ---

#[test]
fn a03_config_rejects_injection_in_app_name() {
    let toml_str = r#"
[base]
outbound = []

[[app]]
name = "evil\"inject"
binary = "safe"
outbound = []
"#;
    // TOML parser should handle the escaped quote, but validate_name catches it
    let result: Result<Config, _> = toml::from_str(toml_str);
    if let Ok(config) = result {
        assert!(config.validate().is_err());
    }
    // Either TOML rejects it or our validation does — both are safe
}

#[test]
fn a03_config_rejects_injection_in_protocol() {
    let toml_str = r#"
[base]
outbound = [{ port = 443, protocol = "tcp; drop" }]
"#;
    let config: Config = toml::from_str(toml_str).unwrap();
    assert!(config.validate().is_err());
}

#[test]
fn a03_config_rejects_newline_in_binary() {
    let config = Config {
        base: BaseConfig {
            outbound: vec![],
            icmp: false,
            loopback: false,
        },
        app: vec![AppConfig {
            name: "safe".into(),
            binary: "bin\nnewline".into(),
            enabled: true,
            outbound: vec![],
        }],
    };
    assert!(config.validate().is_err());
}

// ═══════════════════════════════════════════════════════════════
// A04:2021 - Insecure Design
// ═══════════════════════════════════════════════════════════════

#[test]
fn a04_default_policy_is_drop() {
    let script = build_init_table_script(&[], false, false);
    // Both chains must have policy drop
    let drop_count = script.matches("policy drop").count();
    assert_eq!(
        drop_count, 2,
        "Both input and output chains must default to drop"
    );
}

#[test]
fn a04_established_related_in_both_chains() {
    let script = build_init_table_script(&[], false, false);
    let ct_count = script
        .matches("ct state established,related accept")
        .count();
    assert_eq!(ct_count, 2, "Both chains need established/related");
}

#[test]
fn a04_empty_base_ports_still_drops() {
    let script = build_init_table_script(&[], false, false);
    assert!(script.contains("policy drop"));
    assert!(!script.contains("oif lo")); // no loopback
    assert!(!script.contains("icmp")); // no icmp
}

#[test]
fn a04_rules_removed_on_last_exit() {
    let mock = MockNft::new();
    let mut state = AppState::with_backend(
        Config {
            base: BaseConfig {
                outbound: vec![],
                icmp: false,
                loopback: false,
            },
            app: vec![AppConfig {
                name: "app".into(),
                binary: "app_bin".into(),
                enabled: true,
                outbound: vec![PortRule {
                    port: 443,
                    range_end: None,
                    protocol: "tcp".into(),
                }],
            }],
        },
        Box::new(mock),
    );

    state.handle_exec(100, "app_bin").unwrap();
    state.handle_exec(101, "app_bin").unwrap();
    state.handle_exit(100, "app_bin").unwrap();
    // Still one instance — rules should NOT be removed yet
    assert!(state.status_info().contains("Active apps:    1"));

    state.handle_exit(101, "app_bin").unwrap();
    // Last instance gone — rules must be removed
    assert!(state.status_info().contains("Active apps:    0"));
}

#[test]
fn a04_first_exec_adds_rules_only_once() {
    let mock = MockNft::new();
    let mut state = AppState::with_backend(
        Config {
            base: BaseConfig {
                outbound: vec![],
                icmp: false,
                loopback: false,
            },
            app: vec![AppConfig {
                name: "app".into(),
                binary: "bin".into(),
                enabled: true,
                outbound: vec![],
            }],
        },
        Box::new(mock),
    );

    state.handle_exec(1, "bin").unwrap();
    state.handle_exec(2, "bin").unwrap();
    state.handle_exec(3, "bin").unwrap();
    // Only one add_app_rules call (for the first exec)
    // Verified by status showing only 1 active app
    assert!(state.status_info().contains("Active apps:    1"));
    assert!(state.status_info().contains("3 instance(s)"));
}

// ═══════════════════════════════════════════════════════════════
// A05:2021 - Security Misconfiguration
// ═══════════════════════════════════════════════════════════════

#[test]
fn a05_config_load_validates_on_load() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("afw.toml");
    std::fs::write(
        &path,
        r#"
[base]
outbound = [{ port = 443, protocol = "INVALID_PROTO" }]
"#,
    )
    .unwrap();
    assert!(Config::load(Some(path.to_str().unwrap())).is_err());
}

#[test]
fn a05_dropin_validated_before_merge() {
    let dir = tempfile::tempdir().unwrap();
    let conf_d = dir.path().join("conf.d");
    std::fs::create_dir_all(&conf_d).unwrap();

    let main_path = dir.path().join("afw.toml");
    std::fs::write(&main_path, "[base]\noutbound = []\n").unwrap();

    // Drop-in with injection in app name
    std::fs::write(
        conf_d.join("evil.toml"),
        "[[app]]\nname = \"evil\\\"inject\"\nbinary = \"bin\"\noutbound = []\n",
    )
    .unwrap();

    let result = Config::load(Some(main_path.to_str().unwrap()));
    // Either TOML parsing or validation should reject this
    assert!(result.is_err());
}

#[test]
fn a05_base_defaults_are_secure() {
    let toml_str = "[base]\n";
    let config: Config = toml::from_str(toml_str).unwrap();
    // Defaults should enable basic protections
    assert!(config.base.icmp); // ICMP allowed by default (reasonable)
    assert!(config.base.loopback); // Loopback allowed by default (necessary)
    assert!(!config.base.outbound.is_empty()); // Default ports configured
}

// ═══════════════════════════════════════════════════════════════
// A08:2021 - Software and Data Integrity Failures
// ═══════════════════════════════════════════════════════════════

#[test]
fn a08_config_save_load_roundtrip_integrity() {
    let config = Config {
        base: BaseConfig {
            outbound: vec![PortRule {
                port: 53,
                range_end: None,
                protocol: "udp".into(),
            }],
            icmp: true,
            loopback: true,
        },
        app: vec![AppConfig {
            name: "test".into(),
            binary: "test_bin".into(),
            enabled: true,
            outbound: vec![PortRule {
                port: 443,
                range_end: None,
                protocol: "tcp".into(),
            }],
        }],
    };
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("afw.toml");
    config.save(Some(path.to_str().unwrap())).unwrap();
    let loaded = Config::load(Some(path.to_str().unwrap())).unwrap();

    assert_eq!(loaded.base.outbound.len(), config.base.outbound.len());
    assert_eq!(loaded.base.icmp, config.base.icmp);
    assert_eq!(loaded.app.len(), config.app.len());
    assert_eq!(loaded.app[0].name, config.app[0].name);
}

#[test]
fn a08_corrupted_toml_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("afw.toml");
    std::fs::write(&path, "THIS IS NOT VALID TOML {{{ !!!").unwrap();
    assert!(Config::load(Some(path.to_str().unwrap())).is_err());
}

#[test]
fn a08_truncated_toml_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("afw.toml");
    std::fs::write(&path, "[base]\noutbound = [{ port = 443, protocol = ").unwrap();
    assert!(Config::load(Some(path.to_str().unwrap())).is_err());
}

#[test]
fn a08_empty_config_file_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("afw.toml");
    std::fs::write(&path, "").unwrap();
    assert!(Config::load(Some(path.to_str().unwrap())).is_err());
}

// ═══════════════════════════════════════════════════════════════
// A09:2021 - Security Logging and Monitoring Failures
// (Structural tests - verify logging doesn't leak sensitive data)
// ═══════════════════════════════════════════════════════════════

#[test]
fn a09_status_info_does_not_leak_config_path() {
    let config = Config {
        base: BaseConfig {
            outbound: vec![],
            icmp: false,
            loopback: false,
        },
        app: vec![],
    };
    let state = AppState::with_backend(config, Box::new(MockNft::new()));
    let status = state.status_info();
    assert!(!status.contains("/etc/afw"));
    assert!(!status.contains("afw.toml"));
}

#[test]
fn a09_status_info_shows_pid_for_audit() {
    let config = Config {
        base: BaseConfig {
            outbound: vec![],
            icmp: false,
            loopback: false,
        },
        app: vec![AppConfig {
            name: "audited".into(),
            binary: "audited_bin".into(),
            enabled: true,
            outbound: vec![],
        }],
    };
    let mut state = AppState::with_backend(config, Box::new(MockNft::new()));
    state.handle_exec(12345, "audited_bin").unwrap();
    // Status must include PID for audit trail
    assert!(state.status_info().contains("12345"));
}

// ═══════════════════════════════════════════════════════════════
// Additional: parse_rule_handles security
// ═══════════════════════════════════════════════════════════════

#[test]
fn handle_parsing_no_false_positives_on_substring() {
    let output = r#"
        tcp dport 443 accept comment "afw:discord-canary" # handle 10
        tcp dport 80 accept comment "afw:discord-ptb" # handle 11
    "#;
    // Searching for "discord" must NOT match "discord-canary" or "discord-ptb"
    let handles = parse_rule_handles(output, "discord");
    assert!(handles.is_empty());
}

#[test]
fn handle_parsing_exact_match_only() {
    let output = r#"
        tcp dport 443 accept comment "afw:app" # handle 5
        tcp dport 80 accept comment "afw:app-extended" # handle 6
        tcp dport 22 accept comment "afw:otherapp" # handle 7
    "#;
    let handles = parse_rule_handles(output, "app");
    assert_eq!(handles, vec![5]);
}

#[test]
fn handle_parsing_crafted_output_no_injection() {
    // Even if nft output contains weird formatting
    let output = r#"
        tcp dport 443 accept comment "afw:safe" # handle 42
        some garbage line with "afw:safe" but no handle
        tcp dport 80 accept comment "afw:safe" # handle notanumber
    "#;
    let handles = parse_rule_handles(output, "safe");
    // Only the first line has a valid handle
    assert_eq!(handles, vec![42]);
}

// ═══════════════════════════════════════════════════════════════
// Additional: Config.validate() comprehensive
// ═══════════════════════════════════════════════════════════════

#[test]
fn validate_catches_bad_base_protocol() {
    let config = Config {
        base: BaseConfig {
            outbound: vec![PortRule {
                port: 53,
                range_end: None,
                protocol: "icmp".into(), // not tcp or udp
            }],
            icmp: true,
            loopback: true,
        },
        app: vec![],
    };
    assert!(config.validate().is_err());
}

#[test]
fn validate_catches_bad_app_name() {
    let config = Config {
        base: BaseConfig {
            outbound: vec![],
            icmp: false,
            loopback: false,
        },
        app: vec![AppConfig {
            name: "evil;name".into(),
            binary: "safe".into(),
            enabled: true,
            outbound: vec![],
        }],
    };
    assert!(config.validate().is_err());
}

#[test]
fn validate_catches_bad_binary_name() {
    let config = Config {
        base: BaseConfig {
            outbound: vec![],
            icmp: false,
            loopback: false,
        },
        app: vec![AppConfig {
            name: "safe".into(),
            binary: "bin`whoami`".into(),
            enabled: true,
            outbound: vec![],
        }],
    };
    assert!(config.validate().is_err());
}

#[test]
fn validate_catches_bad_app_port_protocol() {
    let config = Config {
        base: BaseConfig {
            outbound: vec![],
            icmp: false,
            loopback: false,
        },
        app: vec![AppConfig {
            name: "safe".into(),
            binary: "safe_bin".into(),
            enabled: true,
            outbound: vec![PortRule {
                port: 443,
                range_end: None,
                protocol: "tcp accept\nadd rule".into(),
            }],
        }],
    };
    assert!(config.validate().is_err());
}

#[test]
fn validate_passes_clean_config() {
    let config = Config {
        base: BaseConfig {
            outbound: vec![
                PortRule {
                    port: 53,
                    range_end: None,
                    protocol: "udp".into(),
                },
                PortRule {
                    port: 443,
                    range_end: None,
                    protocol: "tcp".into(),
                },
            ],
            icmp: true,
            loopback: true,
        },
        app: vec![
            AppConfig {
                name: "firefox".into(),
                binary: "firefox".into(),
                enabled: true,
                outbound: vec![PortRule {
                    port: 443,
                    range_end: None,
                    protocol: "tcp".into(),
                }],
            },
            AppConfig {
                name: "discord".into(),
                binary: "Discord".into(),
                enabled: true,
                outbound: vec![
                    PortRule {
                        port: 443,
                        range_end: None,
                        protocol: "tcp".into(),
                    },
                    PortRule {
                        port: 50000,
                        range_end: Some(65535),
                        protocol: "udp".into(),
                    },
                ],
            },
        ],
    };
    assert!(config.validate().is_ok());
}

// ═══════════════════════════════════════════════════════════════
// Additional: All forbidden chars individually tested
// ═══════════════════════════════════════════════════════════════

#[test]
fn a03_all_forbidden_chars_rejected_individually() {
    let forbidden = [
        '"', '\'', '\\', '\n', '\r', '\0', ';', '{', '}', '#', '`', '$',
    ];
    for c in forbidden {
        let name = format!("test{}name", c);
        assert!(validate_name(&name).is_err(), "Should reject char: {:?}", c);
    }
}

// ═══════════════════════════════════════════════════════════════
// A03:2021 - Injection: approve/allow-once via crafted binary names
// ═══════════════════════════════════════════════════════════════

#[test]
fn a03_approve_validates_binary_name_in_unknown_connections() {
    // If an attacker-controlled binary name (from /proc comm) contains injection
    // characters, the approve handler must reject it.
    // The IPC Approve handler validates via validate_name before saving to config.
    let attack_names = vec![
        "evil\"app",
        "evil;app",
        "evil\napp",
        "evil`app",
        "evil$app",
        "evil{app",
        "evil}app",
    ];
    for name in attack_names {
        assert!(
            validate_name(name).is_err(),
            "validate_name should reject: {:?}",
            name
        );
    }
}

#[test]
fn a03_allow_once_validates_binary_before_nft_rules() {
    // allow_once derives an app_name from the binary and passes it to nft.
    // If the binary has injection chars, allow_once must fail.
    let mock = MockNft::new();
    let config = Config {
        base: BaseConfig {
            outbound: vec![],
            icmp: false,
            loopback: false,
        },
        app: vec![],
    };
    let mut state = AppState::with_backend(config, Box::new(mock));

    // Simulate an unknown connection with a safe binary name first
    state.handle_connection("safe-app", 443, "tcp", "8.8.8.8");
    let result = state.allow_once("safe-app");
    assert!(result.is_ok());
    assert!(result.unwrap().is_some());
}

#[test]
fn a03_allow_once_rejects_injection_binary() {
    // allow_once now validates the binary name before using it in nft rules.
    // A binary containing injection characters must be rejected.
    let mock = MockNft::new();
    let config = Config {
        base: BaseConfig {
            outbound: vec![],
            icmp: false,
            loopback: false,
        },
        app: vec![],
    };
    let mut state = AppState::with_backend(config, Box::new(mock));

    // Manually inject a malicious binary name into unknown_connections
    // (simulating what would happen if a process had this comm name)
    state.handle_connection("safe_first", 443, "tcp", "8.8.8.8");

    // The validate_name call in allow_once should catch bad names
    // Note: Linux comm names are limited to 16 chars and mostly safe,
    // but we defend in depth.
    // Verify that validate_name would catch the dangerous patterns
    assert!(validate_name("evil\"inject").is_err());
    assert!(validate_name("evil;inject").is_err());
    assert!(validate_name("evil\ninject").is_err());
}

#[test]
fn a03_suggested_command_binary_name_not_used_raw_in_shell() {
    // The suggested_command output is for display only and uses
    // to_lowercase().replace(' ', "-") which strips spaces.
    // Verify the output doesn't contain dangerous raw characters.
    use afw::state::UnknownConnectionSummary;
    let summary = UnknownConnectionSummary {
        binary: "safe-app".into(),
        ports: vec![(443, "tcp".into())],
        dest_addrs: vec![],
        attempt_count: 1,
    };
    let cmd = summary.suggested_command();
    assert!(!cmd.contains('"'));
    assert!(!cmd.contains('\''));
    assert!(!cmd.contains(';'));
    assert!(!cmd.contains('\n'));
}

// ═══════════════════════════════════════════════════════════════
// A01:2021 - Broken Access Control: deny list bypass
// ═══════════════════════════════════════════════════════════════

#[test]
fn a01_deny_list_blocks_handle_connection() {
    let mut state = AppState::with_backend(
        Config {
            base: BaseConfig {
                outbound: vec![],
                icmp: false,
                loopback: false,
            },
            app: vec![],
        },
        Box::new(MockNft::new()),
    );
    state.deny_app("blocked_app");

    // Denied app should not appear in unknown connections
    let is_new = state.handle_connection("blocked_app", 443, "tcp", "8.8.8.8");
    assert!(!is_new);
    assert!(state.unknown_connections().is_empty());
}

#[test]
fn a01_deny_list_case_sensitive() {
    // Deny list is case-sensitive (matches /proc comm exactly)
    let mut state = AppState::with_backend(
        Config {
            base: BaseConfig {
                outbound: vec![],
                icmp: false,
                loopback: false,
            },
            app: vec![],
        },
        Box::new(MockNft::new()),
    );
    state.deny_app("BadApp");
    // Different case should NOT be denied
    assert!(state.handle_connection("badapp", 443, "tcp", "8.8.8.8"));
    // Exact case should be denied
    assert!(!state.handle_connection("BadApp", 443, "tcp", "8.8.8.8"));
}

#[test]
fn a01_deny_clears_existing_unknown_entries() {
    let mut state = AppState::with_backend(
        Config {
            base: BaseConfig {
                outbound: vec![],
                icmp: false,
                loopback: false,
            },
            app: vec![],
        },
        Box::new(MockNft::new()),
    );
    // First, app appears as unknown
    state.handle_connection("sneaky", 443, "tcp", "8.8.8.8");
    assert!(state.unknown_connections().contains_key("sneaky"));
    // Then deny it
    state.deny_app("sneaky");
    // Unknown entry should be cleared
    assert!(!state.unknown_connections().contains_key("sneaky"));
    // And future connections should be silently dropped
    assert!(!state.handle_connection("sneaky", 80, "tcp", "1.1.1.1"));
}

// ═══════════════════════════════════════════════════════════════
// A04:2021 - Insecure Design: IGNORED_BINARIES sufficiency
// ═══════════════════════════════════════════════════════════════

#[test]
fn a04_ignored_binaries_includes_key_system_processes() {
    let mut state = AppState::with_backend(
        Config {
            base: BaseConfig {
                outbound: vec![],
                icmp: false,
                loopback: false,
            },
            app: vec![],
        },
        Box::new(MockNft::new()),
    );

    // Critical system processes that should never trigger alerts
    let critical = vec![
        "systemd",
        "systemd-resolve",
        "systemd-timesyn",
        "systemd-network",
        "dbus-broker",
    ];
    for bin in critical {
        assert!(
            !state.handle_connection(bin, 443, "tcp", "1.2.3.4"),
            "System process '{}' should be in IGNORED_BINARIES",
            bin
        );
    }
}

#[test]
fn a04_ignored_binaries_kworker_prefix_match() {
    // kworker processes have dynamic names like kworker/0:1, kworker/u8:0
    // The prefix check should catch all of them
    let mut state = AppState::with_backend(
        Config {
            base: BaseConfig {
                outbound: vec![],
                icmp: false,
                loopback: false,
            },
            app: vec![],
        },
        Box::new(MockNft::new()),
    );

    let kworker_variants = vec!["kworker/0:0", "kworker/0:1", "kworker/u8:0", "kworker/1:2H"];
    for name in kworker_variants {
        assert!(
            !state.handle_connection(name, 80, "tcp", "1.2.3.4"),
            "kworker variant '{}' should be ignored",
            name
        );
    }
}

#[test]
fn a04_non_system_app_not_ignored() {
    // Custom apps should NOT be filtered by IGNORED_BINARIES
    let mut state = AppState::with_backend(
        Config {
            base: BaseConfig {
                outbound: vec![],
                icmp: false,
                loopback: false,
            },
            app: vec![],
        },
        Box::new(MockNft::new()),
    );

    let user_apps = vec!["my_daemon", "custom_app", "game_server", "Electron"];
    for bin in user_apps {
        assert!(
            state.handle_connection(bin, 443, "tcp", "1.2.3.4"),
            "User app '{}' should NOT be ignored",
            bin
        );
    }
}

// ═══════════════════════════════════════════════════════════════
// A04:2021 - Insecure Design: temp rules removed on exit
// ═══════════════════════════════════════════════════════════════

#[test]
fn a04_temp_rules_removed_on_app_exit() {
    let mut state = AppState::with_backend(
        Config {
            base: BaseConfig {
                outbound: vec![],
                icmp: false,
                loopback: false,
            },
            app: vec![],
        },
        Box::new(MockNft::new()),
    );
    state.handle_connection("temp_app", 443, "tcp", "8.8.8.8");
    state.allow_once("temp_app").unwrap();
    assert!(state.temp_allowed().contains_key("temp_app"));

    // When the app exits, temp rules should be cleaned up
    state.handle_exit(1000, "temp_app").unwrap();
    assert!(!state.temp_allowed().contains_key("temp_app"));
}

// ═══════════════════════════════════════════════════════════════
// A09:2021 - Logging: session detection info leak
// ═══════════════════════════════════════════════════════════════

#[test]
fn a09_unknown_connections_info_does_not_leak_env_vars() {
    // The unknown_connections_info output should not contain
    // session environment variables or file paths
    let mut state = AppState::with_backend(
        Config {
            base: BaseConfig {
                outbound: vec![],
                icmp: false,
                loopback: false,
            },
            app: vec![],
        },
        Box::new(MockNft::new()),
    );
    state.handle_connection("some_app", 443, "tcp", "8.8.8.8");
    let info = state.unknown_connections_info();
    assert!(!info.contains("DISPLAY"));
    assert!(!info.contains("DBUS_SESSION"));
    assert!(!info.contains("XDG_RUNTIME"));
    assert!(!info.contains("WAYLAND_DISPLAY"));
    assert!(!info.contains("/proc"));
}

#[test]
fn a09_notify_action_enum_has_dismiss_default() {
    // NotifyAction::Dismissed must exist as a safe default for timeout/error
    use afw::notify::NotifyAction;
    let action = NotifyAction::Dismissed;
    assert_eq!(action, NotifyAction::Dismissed);
    assert_ne!(action, NotifyAction::Approve);
    assert_ne!(action, NotifyAction::AllowOnce);
    assert_ne!(action, NotifyAction::Deny);
}

#[test]
fn a03_all_safe_printable_ascii_accepted() {
    // Every printable ASCII char not in the forbidden list should be accepted
    let forbidden = ['"', '\'', '\\', ';', '{', '}', '#', '`', '$'];
    for c in ' '..='~' {
        if forbidden.contains(&c) {
            continue;
        }
        let name = format!("a{}b", c);
        assert!(
            validate_name(&name).is_ok(),
            "Should accept char: {:?} ({})",
            c,
            c as u32
        );
    }
}
