use afw::config::PortRule;
use afw::nft::{
    build_add_app_rules_script, build_init_table_script, format_port_rule, parse_rule_handles,
};

// === format_port_rule ===

#[test]
fn format_single_tcp_port() {
    let rule = PortRule {
        port: 443,
        range_end: None,
        protocol: "tcp".into(),
    };
    assert_eq!(format_port_rule(&rule), "tcp dport 443 accept");
}

#[test]
fn format_single_udp_port() {
    let rule = PortRule {
        port: 53,
        range_end: None,
        protocol: "udp".into(),
    };
    assert_eq!(format_port_rule(&rule), "udp dport 53 accept");
}

#[test]
fn format_tcp_port_range() {
    let rule = PortRule {
        port: 27015,
        range_end: Some(27050),
        protocol: "tcp".into(),
    };
    assert_eq!(format_port_rule(&rule), "tcp dport 27015-27050 accept");
}

#[test]
fn format_udp_port_range() {
    let rule = PortRule {
        port: 50000,
        range_end: Some(50100),
        protocol: "udp".into(),
    };
    assert_eq!(format_port_rule(&rule), "udp dport 50000-50100 accept");
}

#[test]
fn format_port_80() {
    let rule = PortRule {
        port: 80,
        range_end: None,
        protocol: "tcp".into(),
    };
    assert_eq!(format_port_rule(&rule), "tcp dport 80 accept");
}

#[test]
fn format_high_port() {
    let rule = PortRule {
        port: 65535,
        range_end: None,
        protocol: "tcp".into(),
    };
    assert_eq!(format_port_rule(&rule), "tcp dport 65535 accept");
}

#[test]
fn format_port_1() {
    let rule = PortRule {
        port: 1,
        range_end: None,
        protocol: "tcp".into(),
    };
    assert_eq!(format_port_rule(&rule), "tcp dport 1 accept");
}

#[test]
fn format_wide_range() {
    let rule = PortRule {
        port: 1024,
        range_end: Some(65535),
        protocol: "tcp".into(),
    };
    assert_eq!(format_port_rule(&rule), "tcp dport 1024-65535 accept");
}

#[test]
fn format_rule_contains_accept() {
    let rule = PortRule {
        port: 443,
        range_end: None,
        protocol: "tcp".into(),
    };
    assert!(format_port_rule(&rule).ends_with("accept"));
}

#[test]
fn format_rule_contains_dport() {
    let rule = PortRule {
        port: 443,
        range_end: None,
        protocol: "tcp".into(),
    };
    assert!(format_port_rule(&rule).contains("dport"));
}

#[test]
fn format_discord_rules() {
    let ports = vec![
        PortRule {
            port: 443,
            range_end: None,
            protocol: "tcp".into(),
        },
        PortRule {
            port: 80,
            range_end: None,
            protocol: "tcp".into(),
        },
        PortRule {
            port: 50000,
            range_end: Some(50100),
            protocol: "udp".into(),
        },
    ];
    let rules: Vec<String> = ports.iter().map(|p| format_port_rule(p)).collect();
    assert_eq!(rules[0], "tcp dport 443 accept");
    assert_eq!(rules[1], "tcp dport 80 accept");
    assert_eq!(rules[2], "udp dport 50000-50100 accept");
}

#[test]
fn format_base_default_ports() {
    let base_ports = vec![
        PortRule {
            port: 53,
            range_end: None,
            protocol: "udp".into(),
        },
        PortRule {
            port: 123,
            range_end: None,
            protocol: "udp".into(),
        },
        PortRule {
            port: 443,
            range_end: None,
            protocol: "tcp".into(),
        },
        PortRule {
            port: 80,
            range_end: None,
            protocol: "tcp".into(),
        },
        PortRule {
            port: 68,
            range_end: None,
            protocol: "udp".into(),
        },
    ];
    let rules: Vec<String> = base_ports.iter().map(|p| format_port_rule(p)).collect();
    assert_eq!(rules.len(), 5);
    assert!(rules[0].starts_with("udp"));
    assert!(rules[2].starts_with("tcp"));
}

// === build_init_table_script ===

#[test]
fn init_script_contains_table_declaration() {
    let script = build_init_table_script(&[], false, false);
    assert!(script.starts_with("table inet afw {"));
}

#[test]
fn init_script_output_chain_policy_drop() {
    let script = build_init_table_script(&[], false, false);
    assert!(script.contains("policy drop"));
}

#[test]
fn init_script_established_related() {
    let script = build_init_table_script(&[], false, false);
    assert!(script.contains("ct state established,related accept"));
}

#[test]
fn init_script_with_loopback() {
    let script = build_init_table_script(&[], false, true);
    assert!(script.contains("oif lo accept"));
    assert!(script.contains("iif lo accept"));
}

#[test]
fn init_script_without_loopback() {
    let script = build_init_table_script(&[], false, false);
    assert!(!script.contains("oif lo"));
    assert!(!script.contains("iif lo"));
}

#[test]
fn init_script_with_icmp() {
    let script = build_init_table_script(&[], true, false);
    assert!(script.contains("meta l4proto icmp accept"));
    assert!(script.contains("meta l4proto icmpv6 accept"));
}

#[test]
fn init_script_without_icmp() {
    let script = build_init_table_script(&[], false, false);
    assert!(!script.contains("meta l4proto icmp"));
}

#[test]
fn init_script_no_icmp_no_loopback() {
    let script = build_init_table_script(&[], false, false);
    assert!(!script.contains("icmp"));
    assert!(!script.contains("oif lo"));
    assert!(script.contains("policy drop"));
}

#[test]
fn init_script_includes_base_ports() {
    let ports = vec![
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
    ];
    let script = build_init_table_script(&ports, false, false);
    assert!(script.contains("udp dport 53 accept"));
    assert!(script.contains("tcp dport 443 accept"));
}

#[test]
fn init_script_has_input_and_output_chains() {
    let script = build_init_table_script(&[], false, false);
    assert!(script.contains("chain output {"));
    assert!(script.contains("chain input {"));
}

#[test]
fn init_script_all_features() {
    let ports = vec![PortRule {
        port: 80,
        range_end: None,
        protocol: "tcp".into(),
    }];
    let script = build_init_table_script(&ports, true, true);
    assert!(script.contains("oif lo accept"));
    assert!(script.contains("iif lo accept"));
    assert!(script.contains("meta l4proto icmp accept"));
    assert!(script.contains("tcp dport 80 accept"));
    assert!(script.contains("table inet afw"));
}

// === build_add_app_rules_script ===

#[test]
fn add_script_single_port() {
    let ports = vec![PortRule {
        port: 443,
        range_end: None,
        protocol: "tcp".into(),
    }];
    let script = build_add_app_rules_script("discord", &ports);
    assert_eq!(
        script,
        "add rule inet afw output tcp dport 443 accept comment \"afw:discord\"\n"
    );
}

#[test]
fn add_script_multiple_ports() {
    let ports = vec![
        PortRule {
            port: 443,
            range_end: None,
            protocol: "tcp".into(),
        },
        PortRule {
            port: 80,
            range_end: None,
            protocol: "tcp".into(),
        },
    ];
    let script = build_add_app_rules_script("firefox", &ports);
    let lines: Vec<&str> = script.lines().collect();
    assert_eq!(lines.len(), 2);
    assert!(lines[0].contains("443"));
    assert!(lines[1].contains("80"));
}

#[test]
fn add_script_empty_ports() {
    let script = build_add_app_rules_script("empty", &[]);
    assert!(script.is_empty());
}

#[test]
fn add_script_comment_contains_app_name() {
    let ports = vec![PortRule {
        port: 443,
        range_end: None,
        protocol: "tcp".into(),
    }];
    let script = build_add_app_rules_script("my-app", &ports);
    assert!(script.contains("comment \"afw:my-app\""));
}

#[test]
fn add_script_with_range() {
    let ports = vec![PortRule {
        port: 50000,
        range_end: Some(50100),
        protocol: "udp".into(),
    }];
    let script = build_add_app_rules_script("discord", &ports);
    assert!(script.contains("udp dport 50000-50100 accept"));
}

// === parse_rule_handles ===

#[test]
fn parse_handles_finds_matching_rules() {
    let output = r#"
        tcp dport 443 accept comment "afw:discord" # handle 42
        tcp dport 80 accept comment "afw:discord" # handle 43
        tcp dport 443 accept comment "afw:firefox" # handle 44
    "#;
    let handles = parse_rule_handles(output, "discord");
    assert_eq!(handles, vec![42, 43]);
}

#[test]
fn parse_handles_ignores_other_apps() {
    let output = r#"
        tcp dport 443 accept comment "afw:firefox" # handle 10
        tcp dport 80 accept comment "afw:firefox" # handle 11
    "#;
    let handles = parse_rule_handles(output, "discord");
    assert!(handles.is_empty());
}

#[test]
fn parse_handles_empty_output() {
    let handles = parse_rule_handles("", "discord");
    assert!(handles.is_empty());
}

#[test]
fn parse_handles_malformed_lines() {
    let output = r#"
        some random line
        tcp dport 443 accept comment "afw:discord"
        tcp dport 80 accept comment "afw:discord" # handle notanumber
        tcp dport 22 accept comment "afw:discord" # handle 99
    "#;
    let handles = parse_rule_handles(output, "discord");
    assert_eq!(handles, vec![99]);
}

#[test]
fn parse_handles_no_comment_lines() {
    let output = r#"
        type filter hook output priority 0; policy drop;
        ct state established,related accept
        oif lo accept
    "#;
    let handles = parse_rule_handles(output, "discord");
    assert!(handles.is_empty());
}

#[test]
fn parse_handles_partial_app_name_no_match() {
    let output = r#"
        tcp dport 443 accept comment "afw:discord-canary" # handle 50
    "#;
    // "discord" should not match "discord-canary"
    let handles = parse_rule_handles(output, "discord");
    assert!(handles.is_empty());
}

// === init script with many base ports ===

#[test]
fn init_script_many_base_ports() {
    let ports: Vec<PortRule> = (0..20)
        .map(|i| PortRule {
            port: 1000 + i,
            range_end: None,
            protocol: if i % 2 == 0 {
                "tcp".into()
            } else {
                "udp".into()
            },
        })
        .collect();
    let script = build_init_table_script(&ports, true, true);
    // All 20 ports should appear in the output
    for i in 0..20u16 {
        assert!(
            script.contains(&format!("dport {} accept", 1000 + i)),
            "Missing port {}",
            1000 + i
        );
    }
    // Still has the table structure
    assert!(script.starts_with("table inet afw {"));
    assert!(script.contains("chain output {"));
    assert!(script.contains("chain input {"));
}

#[test]
fn init_script_base_ports_with_ranges() {
    let ports = vec![
        PortRule {
            port: 1024,
            range_end: Some(2048),
            protocol: "tcp".into(),
        },
        PortRule {
            port: 5000,
            range_end: Some(6000),
            protocol: "udp".into(),
        },
    ];
    let script = build_init_table_script(&ports, false, false);
    assert!(script.contains("tcp dport 1024-2048 accept"));
    assert!(script.contains("udp dport 5000-6000 accept"));
}

// === add script with special chars in app name ===

#[test]
fn add_script_app_name_with_dashes() {
    let ports = vec![PortRule {
        port: 443,
        range_end: None,
        protocol: "tcp".into(),
    }];
    let script = build_add_app_rules_script("my-cool-app", &ports);
    assert!(script.contains("comment \"afw:my-cool-app\""));
}

#[test]
fn add_script_app_name_with_underscores() {
    let ports = vec![PortRule {
        port: 80,
        range_end: None,
        protocol: "tcp".into(),
    }];
    let script = build_add_app_rules_script("my_app_v2", &ports);
    assert!(script.contains("comment \"afw:my_app_v2\""));
}

#[test]
fn add_script_app_name_with_dots() {
    let ports = vec![PortRule {
        port: 8080,
        range_end: None,
        protocol: "tcp".into(),
    }];
    let script = build_add_app_rules_script("app.v3.1", &ports);
    assert!(script.contains("comment \"afw:app.v3.1\""));
}

#[test]
fn add_script_many_ports() {
    let ports: Vec<PortRule> = (0..15)
        .map(|i| PortRule {
            port: 8000 + i,
            range_end: None,
            protocol: "tcp".into(),
        })
        .collect();
    let script = build_add_app_rules_script("big_app", &ports);
    let lines: Vec<&str> = script.lines().collect();
    assert_eq!(lines.len(), 15);
    for (i, line) in lines.iter().enumerate() {
        assert!(
            line.contains(&format!("tcp dport {} accept", 8000 + i as u16)),
            "Line {} missing expected port",
            i
        );
        assert!(line.contains("comment \"afw:big_app\""));
    }
}

#[test]
fn add_script_mixed_protocols() {
    let ports = vec![
        PortRule {
            port: 443,
            range_end: None,
            protocol: "tcp".into(),
        },
        PortRule {
            port: 53,
            range_end: None,
            protocol: "udp".into(),
        },
        PortRule {
            port: 8000,
            range_end: Some(9000),
            protocol: "tcp".into(),
        },
    ];
    let script = build_add_app_rules_script("mixed", &ports);
    let lines: Vec<&str> = script.lines().collect();
    assert_eq!(lines.len(), 3);
    assert!(lines[0].contains("tcp dport 443"));
    assert!(lines[1].contains("udp dport 53"));
    assert!(lines[2].contains("tcp dport 8000-9000"));
}

// === parse_rule_handles with real-world nft output format ===

#[test]
fn parse_handles_real_world_nft_output() {
    let output = r#"table inet afw {
	chain output {
		type filter hook output priority filter; policy drop;
		ct state established,related accept # handle 2
		oif "lo" accept # handle 3
		udp dport 53 accept # handle 4
		tcp dport 443 accept # handle 5
		meta l4proto icmp accept # handle 6
		meta l4proto ipv6-icmp accept # handle 7
		tcp dport 443 accept comment "afw:discord" # handle 8
		tcp dport 80 accept comment "afw:discord" # handle 9
		udp dport 50000-50100 accept comment "afw:discord" # handle 10
		tcp dport 80 accept comment "afw:firefox" # handle 11
		tcp dport 443 accept comment "afw:firefox" # handle 12
	}
}"#;
    let discord_handles = parse_rule_handles(output, "discord");
    assert_eq!(discord_handles, vec![8, 9, 10]);

    let firefox_handles = parse_rule_handles(output, "firefox");
    assert_eq!(firefox_handles, vec![11, 12]);

    let steam_handles = parse_rule_handles(output, "steam");
    assert!(steam_handles.is_empty());
}

#[test]
fn parse_handles_large_handle_numbers() {
    let output = r#"
        tcp dport 443 accept comment "afw:app" # handle 999999
        tcp dport 80 accept comment "afw:app" # handle 1000000
    "#;
    let handles = parse_rule_handles(output, "app");
    assert_eq!(handles, vec![999999, 1000000]);
}

#[test]
fn parse_handles_single_rule() {
    let output = r#"		tcp dport 443 accept comment "afw:solo" # handle 1"#;
    let handles = parse_rule_handles(output, "solo");
    assert_eq!(handles, vec![1]);
}

#[test]
fn parse_handles_tab_indented() {
    let output = "\t\ttcp dport 443 accept comment \"afw:tabapp\" # handle 42\n";
    let handles = parse_rule_handles(output, "tabapp");
    assert_eq!(handles, vec![42]);
}

#[test]
fn parse_handles_comment_substring_no_false_match() {
    // "afw:disc" should not match "afw:discord"
    let output = r#"
        tcp dport 443 accept comment "afw:discord" # handle 10
    "#;
    let handles = parse_rule_handles(output, "disc");
    assert!(handles.is_empty());
}

// === format_port_rule additional ===

#[test]
fn format_port_range_one_apart() {
    let rule = PortRule {
        port: 100,
        range_end: Some(101),
        protocol: "tcp".into(),
    };
    assert_eq!(format_port_rule(&rule), "tcp dport 100-101 accept");
}

#[test]
fn format_port_zero() {
    let rule = PortRule {
        port: 0,
        range_end: None,
        protocol: "tcp".into(),
    };
    assert_eq!(format_port_rule(&rule), "tcp dport 0 accept");
}

// === init script structure tests ===

#[test]
fn init_script_ends_with_closing_brace() {
    let script = build_init_table_script(&[], false, false);
    assert!(script.trim().ends_with('}'));
}

#[test]
fn init_script_base_ports_in_output_chain() {
    // Base ports should appear between "chain output" and "chain input"
    let ports = vec![PortRule {
        port: 12345,
        range_end: None,
        protocol: "tcp".into(),
    }];
    let script = build_init_table_script(&ports, false, false);
    let output_pos = script.find("chain output").unwrap();
    let input_pos = script.find("chain input").unwrap();
    let port_pos = script.find("tcp dport 12345 accept").unwrap();
    assert!(port_pos > output_pos && port_pos < input_pos);
}

#[test]
fn init_script_icmp_in_both_chains() {
    let script = build_init_table_script(&[], true, false);
    // ICMP rules should appear twice (once in output, once in input)
    let count = script.matches("meta l4proto icmp accept").count();
    assert_eq!(
        count, 2,
        "ICMP should appear in both input and output chains"
    );
}

#[test]
fn init_script_loopback_in_both_chains() {
    let script = build_init_table_script(&[], false, true);
    assert!(script.contains("oif lo accept")); // output chain
    assert!(script.contains("iif lo accept")); // input chain
}
