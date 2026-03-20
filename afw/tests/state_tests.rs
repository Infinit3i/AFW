use afw::config::*;
use afw::state::AppState;

fn test_config() -> Config {
    Config {
        base: BaseConfig {
            outbound: vec![
                PortRule { port: 53, range_end: None, protocol: "udp".into() },
            ],
            icmp: true,
            loopback: true,
        },
        app: vec![
            AppConfig {
                name: "discord".into(),
                binary: "Discord".into(),
                enabled: true,
                outbound: vec![
                    PortRule { port: 443, range_end: None, protocol: "tcp".into() },
                ],
            },
            AppConfig {
                name: "firefox".into(),
                binary: "firefox".into(),
                enabled: true,
                outbound: vec![
                    PortRule { port: 80, range_end: None, protocol: "tcp".into() },
                ],
            },
            AppConfig {
                name: "steam".into(),
                binary: "steam".into(),
                enabled: false,
                outbound: vec![
                    PortRule { port: 443, range_end: None, protocol: "tcp".into() },
                ],
            },
        ],
    }
}

// === AppState initialization ===

#[test]
fn new_state_has_correct_config() {
    let config = test_config();
    let state = AppState::new(config.clone());
    assert_eq!(state.config().app.len(), 3);
}

#[test]
fn new_state_no_active_apps() {
    let config = test_config();
    let state = AppState::new(config);
    let status = state.status_info();
    assert!(status.contains("Active apps:    0"));
}

#[test]
fn new_state_reports_monitored_count() {
    let config = test_config();
    let state = AppState::new(config);
    let status = state.status_info();
    assert!(status.contains("Monitored apps: 3"));
}

// === status_info formatting ===

#[test]
fn status_info_contains_header() {
    let config = test_config();
    let state = AppState::new(config);
    let status = state.status_info();
    assert!(status.contains("AFW Status"));
    assert!(status.contains("══════════"));
}

#[test]
fn status_info_no_running_apps_message() {
    let config = test_config();
    let state = AppState::new(config);
    let status = state.status_info();
    assert!(status.contains("No monitored applications currently running."));
}

// === Config access ===

#[test]
fn config_ref_returns_correct_config() {
    let config = test_config();
    let state = AppState::new(config);
    let config_ref = state.config();
    assert_eq!(config_ref.app.len(), 3);
    assert_eq!(config_ref.app[0].name, "discord");
}

#[test]
fn config_base_ports_accessible() {
    let config = test_config();
    let state = AppState::new(config);
    assert_eq!(state.config().base.outbound.len(), 1);
    assert_eq!(state.config().base.outbound[0].port, 53);
}

// === Empty config edge cases ===

#[test]
fn empty_app_list() {
    let config = Config {
        base: BaseConfig {
            outbound: vec![],
            icmp: false,
            loopback: false,
        },
        app: vec![],
    };
    let state = AppState::new(config);
    let status = state.status_info();
    assert!(status.contains("Monitored apps: 0"));
    assert!(status.contains("Active apps:    0"));
}

// Note: handle_exec/handle_exit/reload_config call nft:: functions which require
// root privileges and nftables. Those are tested in integration tests that run
// with appropriate privileges. The tests here verify the pure state/config logic.
