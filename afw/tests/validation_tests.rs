use afw::config::{validate_name, PortRule};

// === validate_name ===

#[test]
fn validate_name_simple() {
    assert!(validate_name("firefox").is_ok());
}

#[test]
fn validate_name_with_dash() {
    assert!(validate_name("code-oss").is_ok());
}

#[test]
fn validate_name_with_underscore() {
    assert!(validate_name("my_app").is_ok());
}

#[test]
fn validate_name_with_dot() {
    assert!(validate_name("gimp-2.10").is_ok());
}

#[test]
fn validate_name_with_space() {
    assert!(validate_name("Plex Media Pla").is_ok());
}

#[test]
fn validate_name_uppercase() {
    assert!(validate_name("Discord").is_ok());
}

#[test]
fn validate_name_empty_rejected() {
    assert!(validate_name("").is_err());
}

#[test]
fn validate_name_too_long_rejected() {
    let long = "a".repeat(65);
    assert!(validate_name(&long).is_err());
}

#[test]
fn validate_name_max_length_ok() {
    let exact = "a".repeat(64);
    assert!(validate_name(&exact).is_ok());
}

// === Injection-preventing rejections ===

#[test]
fn validate_name_rejects_double_quote() {
    assert!(validate_name(r#"foo"bar"#).is_err());
}

#[test]
fn validate_name_rejects_single_quote() {
    assert!(validate_name("foo'bar").is_err());
}

#[test]
fn validate_name_rejects_newline() {
    assert!(validate_name("foo\nbar").is_err());
}

#[test]
fn validate_name_rejects_carriage_return() {
    assert!(validate_name("foo\rbar").is_err());
}

#[test]
fn validate_name_rejects_null() {
    assert!(validate_name("foo\0bar").is_err());
}

#[test]
fn validate_name_rejects_backslash() {
    assert!(validate_name("foo\\bar").is_err());
}

#[test]
fn validate_name_rejects_semicolon() {
    assert!(validate_name("foo;bar").is_err());
}

#[test]
fn validate_name_rejects_braces() {
    assert!(validate_name("foo{bar").is_err());
    assert!(validate_name("foo}bar").is_err());
}

#[test]
fn validate_name_rejects_hash() {
    assert!(validate_name("foo#bar").is_err());
}

#[test]
fn validate_name_rejects_backtick() {
    assert!(validate_name("foo`bar").is_err());
}

#[test]
fn validate_name_rejects_dollar() {
    assert!(validate_name("foo$bar").is_err());
}

#[test]
fn validate_name_rejects_non_ascii() {
    assert!(validate_name("café").is_err());
}

// === Injection attack patterns ===

#[test]
fn validate_name_rejects_nft_comment_injection() {
    // Attempt to break out of nft comment and inject a rule
    let attack = r#"foo" accept; add rule inet afw output accept comment "pwned"#;
    assert!(validate_name(attack).is_err());
}

#[test]
fn validate_name_rejects_newline_injection() {
    let attack = "foo\nadd rule inet afw output accept";
    assert!(validate_name(attack).is_err());
}

#[test]
fn validate_name_rejects_shell_injection() {
    let attack = "foo; rm -rf /";
    assert!(validate_name(attack).is_err());
}

#[test]
fn validate_name_rejects_backtick_injection() {
    let attack = "foo`whoami`bar";
    assert!(validate_name(attack).is_err());
}

#[test]
fn validate_name_rejects_dollar_injection() {
    let attack = "foo$(id)bar";
    assert!(validate_name(attack).is_err());
}

// === PortRule.validate ===

#[test]
fn port_rule_validate_tcp_ok() {
    let rule = PortRule {
        port: 443,
        range_end: None,
        protocol: "tcp".into(),
    };
    assert!(rule.validate().is_ok());
}

#[test]
fn port_rule_validate_udp_ok() {
    let rule = PortRule {
        port: 53,
        range_end: None,
        protocol: "udp".into(),
    };
    assert!(rule.validate().is_ok());
}

#[test]
fn port_rule_validate_range_ok() {
    let rule = PortRule {
        port: 50000,
        range_end: Some(50100),
        protocol: "udp".into(),
    };
    assert!(rule.validate().is_ok());
}

#[test]
fn port_rule_validate_bad_protocol() {
    let rule = PortRule {
        port: 443,
        range_end: None,
        protocol: "sctp".into(),
    };
    assert!(rule.validate().is_err());
}

#[test]
fn port_rule_validate_injection_protocol() {
    // Protocol field injection attempt
    let rule = PortRule {
        port: 443,
        range_end: None,
        protocol: "tcp dport 22 accept\nadd rule inet afw output".into(),
    };
    assert!(rule.validate().is_err());
}

#[test]
fn port_rule_validate_empty_protocol() {
    let rule = PortRule {
        port: 443,
        range_end: None,
        protocol: String::new(),
    };
    assert!(rule.validate().is_err());
}

#[test]
fn port_rule_validate_range_end_less_than_start() {
    let rule = PortRule {
        port: 50100,
        range_end: Some(50000),
        protocol: "tcp".into(),
    };
    assert!(rule.validate().is_err());
}

#[test]
fn port_rule_validate_range_end_equal_to_start() {
    let rule = PortRule {
        port: 50000,
        range_end: Some(50000),
        protocol: "tcp".into(),
    };
    assert!(rule.validate().is_err());
}

// === Real-world binary names that should pass ===

#[test]
fn validate_real_binary_names() {
    let names = [
        "firefox",
        "Discord",
        "code-oss",
        "gimp-2.10",
        "Plex Media Pla",
        "systemd-resolve",
        "wg-quick",
        "qemu-system-x8",
        "1password",
        "soffice.bin",
        "kodi.bin",
        "apt-get",
        "mullvad-daemon",
        "Web Content",
        "Isolated Web Co",
        "RDD Process",
    ];
    for name in names {
        assert!(validate_name(name).is_ok(), "Should accept: {}", name);
    }
}
