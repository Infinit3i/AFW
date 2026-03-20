use afw::config::PortRule;
use afw::nft::format_port_rule;

// === format_port_rule ===

#[test]
fn format_single_tcp_port() {
    let rule = PortRule { port: 443, range_end: None, protocol: "tcp".into() };
    assert_eq!(format_port_rule(&rule), "tcp dport 443 accept");
}

#[test]
fn format_single_udp_port() {
    let rule = PortRule { port: 53, range_end: None, protocol: "udp".into() };
    assert_eq!(format_port_rule(&rule), "udp dport 53 accept");
}

#[test]
fn format_tcp_port_range() {
    let rule = PortRule { port: 27015, range_end: Some(27050), protocol: "tcp".into() };
    assert_eq!(format_port_rule(&rule), "tcp dport 27015-27050 accept");
}

#[test]
fn format_udp_port_range() {
    let rule = PortRule { port: 50000, range_end: Some(50100), protocol: "udp".into() };
    assert_eq!(format_port_rule(&rule), "udp dport 50000-50100 accept");
}

#[test]
fn format_port_80() {
    let rule = PortRule { port: 80, range_end: None, protocol: "tcp".into() };
    assert_eq!(format_port_rule(&rule), "tcp dport 80 accept");
}

#[test]
fn format_high_port() {
    let rule = PortRule { port: 65535, range_end: None, protocol: "tcp".into() };
    assert_eq!(format_port_rule(&rule), "tcp dport 65535 accept");
}

#[test]
fn format_port_1() {
    let rule = PortRule { port: 1, range_end: None, protocol: "tcp".into() };
    assert_eq!(format_port_rule(&rule), "tcp dport 1 accept");
}

#[test]
fn format_wide_range() {
    let rule = PortRule { port: 1024, range_end: Some(65535), protocol: "tcp".into() };
    assert_eq!(format_port_rule(&rule), "tcp dport 1024-65535 accept");
}

#[test]
fn format_rule_contains_accept() {
    let rule = PortRule { port: 443, range_end: None, protocol: "tcp".into() };
    let formatted = format_port_rule(&rule);
    assert!(formatted.ends_with("accept"));
}

#[test]
fn format_rule_contains_dport() {
    let rule = PortRule { port: 443, range_end: None, protocol: "tcp".into() };
    let formatted = format_port_rule(&rule);
    assert!(formatted.contains("dport"));
}

// === Rule generation patterns (verifying what nft would receive) ===

#[test]
fn format_discord_rules() {
    let ports = vec![
        PortRule { port: 443, range_end: None, protocol: "tcp".into() },
        PortRule { port: 80, range_end: None, protocol: "tcp".into() },
        PortRule { port: 50000, range_end: Some(50100), protocol: "udp".into() },
    ];

    let rules: Vec<String> = ports.iter().map(|p| format_port_rule(p)).collect();
    assert_eq!(rules[0], "tcp dport 443 accept");
    assert_eq!(rules[1], "tcp dport 80 accept");
    assert_eq!(rules[2], "udp dport 50000-50100 accept");
}

#[test]
fn format_base_default_ports() {
    let base_ports = vec![
        PortRule { port: 53, range_end: None, protocol: "udp".into() },
        PortRule { port: 123, range_end: None, protocol: "udp".into() },
        PortRule { port: 443, range_end: None, protocol: "tcp".into() },
        PortRule { port: 80, range_end: None, protocol: "tcp".into() },
        PortRule { port: 68, range_end: None, protocol: "udp".into() },
    ];

    let rules: Vec<String> = base_ports.iter().map(|p| format_port_rule(p)).collect();
    assert_eq!(rules.len(), 5);
    assert!(rules[0].starts_with("udp")); // DNS
    assert!(rules[2].starts_with("tcp")); // HTTPS
}
