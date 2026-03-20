use std::sync::Mutex;

use afw::config::*;
use afw::nft::NftBackend;
use afw::state::AppState;

// === Mock NftBackend ===

struct MockNft {
    added: Mutex<Vec<(String, usize)>>,    // (app_name, port_count)
    removed: Mutex<Vec<String>>,           // app_name
    fail_add: Mutex<bool>,
    fail_remove: Mutex<bool>,
}

impl MockNft {
    fn new() -> Self {
        Self {
            added: Mutex::new(Vec::new()),
            removed: Mutex::new(Vec::new()),
            fail_add: Mutex::new(false),
            fail_remove: Mutex::new(false),
        }
    }

    fn set_fail_add(&self, fail: bool) {
        *self.fail_add.lock().unwrap() = fail;
    }

    fn set_fail_remove(&self, fail: bool) {
        *self.fail_remove.lock().unwrap() = fail;
    }
}

impl NftBackend for MockNft {
    fn add_app_rules(&self, app_name: &str, ports: &[PortRule]) -> anyhow::Result<()> {
        if *self.fail_add.lock().unwrap() {
            anyhow::bail!("mock add failure");
        }
        self.added.lock().unwrap().push((app_name.to_string(), ports.len()));
        Ok(())
    }

    fn remove_app_rules(&self, app_name: &str) -> anyhow::Result<()> {
        if *self.fail_remove.lock().unwrap() {
            anyhow::bail!("mock remove failure");
        }
        self.removed.lock().unwrap().push(app_name.to_string());
        Ok(())
    }

    fn list_rules(&self) -> anyhow::Result<String> {
        Ok("mock rules".into())
    }

    fn init_table(&self, _base_ports: &[PortRule], _icmp: bool, _loopback: bool) -> anyhow::Result<()> {
        Ok(())
    }

    fn cleanup(&self) -> anyhow::Result<()> {
        Ok(())
    }
}

// === Test helpers ===

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
                    PortRule { port: 80, range_end: None, protocol: "tcp".into() },
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

fn mock_state() -> AppState {
    AppState::with_backend(test_config(), Box::new(MockNft::new()))
}

fn mock_state_with(config: Config) -> AppState {
    AppState::with_backend(config, Box::new(MockNft::new()))
}

// === Initialization ===

#[test]
fn new_state_has_correct_config() {
    let state = mock_state();
    assert_eq!(state.config().app.len(), 3);
}

#[test]
fn new_state_no_active_apps() {
    let state = mock_state();
    let status = state.status_info();
    assert!(status.contains("Active apps:    0"));
}

#[test]
fn new_state_reports_monitored_count() {
    let state = mock_state();
    let status = state.status_info();
    assert!(status.contains("Monitored apps: 3"));
}

// === handle_exec ===

#[test]
fn handle_exec_monitored_app_adds_rules() {
    let mock = MockNft::new();
    let mut state = AppState::with_backend(test_config(), Box::new(mock));
    state.handle_exec(1000, "Discord").unwrap();

    let status = state.status_info();
    assert!(status.contains("discord"));
    assert!(status.contains("1000"));
    assert!(status.contains("Active apps:    1"));
}

#[test]
fn handle_exec_unmonitored_app_noop() {
    let mut state = mock_state();
    state.handle_exec(1000, "unknown_app").unwrap();

    let status = state.status_info();
    assert!(status.contains("Active apps:    0"));
}

#[test]
fn handle_exec_disabled_app_noop() {
    let mut state = mock_state();
    // "steam" is disabled so "steam" binary won't be in binary_map
    state.handle_exec(1000, "steam").unwrap();

    let status = state.status_info();
    assert!(status.contains("Active apps:    0"));
}

#[test]
fn handle_exec_second_instance_no_duplicate_rules() {
    let mock = MockNft::new();
    let mut state = AppState::with_backend(test_config(), Box::new(mock));

    state.handle_exec(1000, "Discord").unwrap();
    state.handle_exec(1001, "Discord").unwrap();

    let status = state.status_info();
    assert!(status.contains("2 instance(s)"));
    // nft.add_app_rules should have been called only once (for first instance)
    // We can verify via status that both PIDs are tracked
    assert!(status.contains("1000"));
    assert!(status.contains("1001"));
}

#[test]
fn handle_exec_different_apps_both_get_rules() {
    let mut state = mock_state();

    state.handle_exec(1000, "Discord").unwrap();
    state.handle_exec(2000, "firefox").unwrap();

    let status = state.status_info();
    assert!(status.contains("Active apps:    2"));
    assert!(status.contains("discord"));
    assert!(status.contains("firefox"));
}

#[test]
fn handle_exec_nft_failure_propagates() {
    let mock = MockNft::new();
    mock.set_fail_add(true);
    let mut state = AppState::with_backend(test_config(), Box::new(mock));

    let result = state.handle_exec(1000, "Discord");
    assert!(result.is_err());
}

// === handle_exit ===

#[test]
fn handle_exit_last_instance_removes_rules() {
    let mut state = mock_state();
    state.handle_exec(1000, "Discord").unwrap();
    state.handle_exit(1000, "Discord").unwrap();

    let status = state.status_info();
    assert!(status.contains("Active apps:    0"));
    assert!(status.contains("No monitored applications currently running."));
}

#[test]
fn handle_exit_not_last_instance_keeps_rules() {
    let mut state = mock_state();
    state.handle_exec(1000, "Discord").unwrap();
    state.handle_exec(1001, "Discord").unwrap();
    state.handle_exit(1000, "Discord").unwrap();

    let status = state.status_info();
    assert!(status.contains("Active apps:    1"));
    assert!(status.contains("1 instance(s)"));
}

#[test]
fn handle_exit_unmonitored_app_noop() {
    let mut state = mock_state();
    // No error, just silently ignored
    state.handle_exit(1000, "unknown_app").unwrap();
    assert!(state.status_info().contains("Active apps:    0"));
}

#[test]
fn handle_exit_unknown_pid_noop() {
    let mut state = mock_state();
    state.handle_exec(1000, "Discord").unwrap();
    // Exit a PID that was never exec'd for this app
    state.handle_exit(9999, "Discord").unwrap();

    // Original PID still active
    let status = state.status_info();
    assert!(status.contains("Active apps:    1"));
    assert!(status.contains("1000"));
}

#[test]
fn handle_exit_nft_failure_propagates() {
    let mock = MockNft::new();
    let mut state = AppState::with_backend(test_config(), Box::new(mock));
    state.handle_exec(1000, "Discord").unwrap();

    // Now make remove fail - we need a new approach since mock is moved
    // Instead, test by making a mock that fails on remove from the start
    let mock2 = MockNft::new();
    mock2.set_fail_remove(true);
    let mut state2 = AppState::with_backend(test_config(), Box::new(mock2));
    state2.handle_exec(1000, "Discord").unwrap();
    let result = state2.handle_exit(1000, "Discord");
    assert!(result.is_err());
}

#[test]
fn handle_exit_cleans_up_pid_set() {
    let mut state = mock_state();
    state.handle_exec(1000, "Discord").unwrap();
    state.handle_exec(1001, "Discord").unwrap();
    state.handle_exit(1000, "Discord").unwrap();
    state.handle_exit(1001, "Discord").unwrap();

    // After all PIDs exit, status should show no running apps
    let status = state.status_info();
    assert!(status.contains("No monitored applications currently running."));
}

// === Multi-instance lifecycle ===

#[test]
fn exec_exit_exec_reopens_rules() {
    let mut state = mock_state();

    // First instance
    state.handle_exec(1000, "Discord").unwrap();
    assert!(state.status_info().contains("Active apps:    1"));

    // Exit
    state.handle_exit(1000, "Discord").unwrap();
    assert!(state.status_info().contains("Active apps:    0"));

    // New instance should re-add rules
    state.handle_exec(2000, "Discord").unwrap();
    assert!(state.status_info().contains("Active apps:    1"));
    assert!(state.status_info().contains("2000"));
}

#[test]
fn multiple_apps_independent_lifecycle() {
    let mut state = mock_state();

    state.handle_exec(1000, "Discord").unwrap();
    state.handle_exec(2000, "firefox").unwrap();
    assert!(state.status_info().contains("Active apps:    2"));

    // Only discord exits
    state.handle_exit(1000, "Discord").unwrap();
    assert!(state.status_info().contains("Active apps:    1"));
    assert!(state.status_info().contains("firefox"));
    assert!(!state.status_info().contains("discord"));

    // Firefox exits
    state.handle_exit(2000, "firefox").unwrap();
    assert!(state.status_info().contains("Active apps:    0"));
}

#[test]
fn rapid_exec_exit_same_pid() {
    let mut state = mock_state();

    state.handle_exec(1000, "Discord").unwrap();
    state.handle_exit(1000, "Discord").unwrap();
    state.handle_exec(1000, "Discord").unwrap();
    state.handle_exit(1000, "Discord").unwrap();

    assert!(state.status_info().contains("Active apps:    0"));
}

// === status_info formatting ===

#[test]
fn status_info_contains_header() {
    let state = mock_state();
    let status = state.status_info();
    assert!(status.contains("AFW Status"));
    assert!(status.contains("══════════"));
}

#[test]
fn status_info_no_running_apps_message() {
    let state = mock_state();
    assert!(state.status_info().contains("No monitored applications currently running."));
}

#[test]
fn status_info_shows_active_app_with_pids() {
    let mut state = mock_state();
    state.handle_exec(1234, "Discord").unwrap();

    let status = state.status_info();
    assert!(status.contains("discord"));
    assert!(status.contains("1234"));
    assert!(status.contains("1 instance(s)"));
}

#[test]
fn status_info_shows_port_rules() {
    let mut state = mock_state();
    state.handle_exec(1000, "Discord").unwrap();

    let status = state.status_info();
    assert!(status.contains("443/tcp"));
    assert!(status.contains("80/tcp"));
}

#[test]
fn status_info_multiple_instances_shows_count() {
    let mut state = mock_state();
    state.handle_exec(1000, "Discord").unwrap();
    state.handle_exec(1001, "Discord").unwrap();
    state.handle_exec(1002, "Discord").unwrap();

    assert!(state.status_info().contains("3 instance(s)"));
}

#[test]
fn status_info_after_all_exit() {
    let mut state = mock_state();
    state.handle_exec(1000, "Discord").unwrap();
    state.handle_exit(1000, "Discord").unwrap();

    assert!(state.status_info().contains("No monitored applications currently running."));
}

// === Config access ===

#[test]
fn config_ref_returns_correct_config() {
    let state = mock_state();
    assert_eq!(state.config().app.len(), 3);
    assert_eq!(state.config().app[0].name, "discord");
}

#[test]
fn config_base_ports_accessible() {
    let state = mock_state();
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
    let state = mock_state_with(config);
    let status = state.status_info();
    assert!(status.contains("Monitored apps: 0"));
    assert!(status.contains("Active apps:    0"));
}

#[test]
fn all_apps_disabled() {
    let config = Config {
        base: BaseConfig {
            outbound: vec![],
            icmp: false,
            loopback: false,
        },
        app: vec![AppConfig {
            name: "test".into(),
            binary: "test".into(),
            enabled: false,
            outbound: vec![],
        }],
    };
    let mut state = mock_state_with(config);
    // Binary won't be in map since disabled
    state.handle_exec(1000, "test").unwrap();
    assert!(state.status_info().contains("Active apps:    0"));
}

// === nft backend access ===

#[test]
fn nft_backend_accessible() {
    let state = mock_state();
    let rules = state.nft().list_rules().unwrap();
    assert_eq!(rules, "mock rules");
}

// === handle_exec/exit with many PIDs ===

#[test]
fn handle_exec_many_pids_same_app() {
    let mut state = mock_state();
    for pid in 1000..1100 {
        state.handle_exec(pid, "Discord").unwrap();
    }
    let status = state.status_info();
    assert!(status.contains("Active apps:    1"));
    assert!(status.contains("100 instance(s)"));
}

#[test]
fn handle_exec_exit_many_pids_all_exit() {
    let mut state = mock_state();
    for pid in 1000..1100 {
        state.handle_exec(pid, "Discord").unwrap();
    }
    for pid in 1000..1100 {
        state.handle_exit(pid, "Discord").unwrap();
    }
    let status = state.status_info();
    assert!(status.contains("Active apps:    0"));
    assert!(status.contains("No monitored applications currently running."));
}

#[test]
fn handle_exec_exit_many_pids_partial_exit() {
    let mut state = mock_state();
    for pid in 1000..1050 {
        state.handle_exec(pid, "Discord").unwrap();
    }
    // Exit only half
    for pid in 1000..1025 {
        state.handle_exit(pid, "Discord").unwrap();
    }
    let status = state.status_info();
    assert!(status.contains("Active apps:    1"));
    assert!(status.contains("25 instance(s)"));
}

#[test]
fn handle_exec_many_different_apps() {
    let apps: Vec<AppConfig> = (0..10)
        .map(|i| AppConfig {
            name: format!("app_{}", i),
            binary: format!("bin_{}", i),
            enabled: true,
            outbound: vec![PortRule {
                port: 8000 + i as u16,
                range_end: None,
                protocol: "tcp".into(),
            }],
        })
        .collect();
    let config = Config {
        base: BaseConfig {
            outbound: vec![],
            icmp: false,
            loopback: false,
        },
        app: apps,
    };
    let mut state = mock_state_with(config);

    for i in 0..10u32 {
        state.handle_exec(1000 + i, &format!("bin_{}", i)).unwrap();
    }
    let status = state.status_info();
    assert!(status.contains("Active apps:    10"));
}

// === binary_map correctness after construction ===

#[test]
fn binary_map_maps_binary_to_app_name() {
    let mut state = mock_state();
    // "Discord" binary maps to "discord" app name
    state.handle_exec(1000, "Discord").unwrap();
    let status = state.status_info();
    // The status shows app name "discord", not binary name "Discord"
    assert!(status.contains("discord"));
}

#[test]
fn binary_map_skips_disabled_in_state() {
    let mut state = mock_state();
    // "steam" is disabled, so its binary should not be recognized
    state.handle_exec(1000, "steam").unwrap();
    assert!(state.status_info().contains("Active apps:    0"));
}

#[test]
fn binary_map_all_enabled_apps_present() {
    let config = Config {
        base: BaseConfig {
            outbound: vec![],
            icmp: false,
            loopback: false,
        },
        app: vec![
            AppConfig {
                name: "a".into(),
                binary: "bin_a".into(),
                enabled: true,
                outbound: vec![],
            },
            AppConfig {
                name: "b".into(),
                binary: "bin_b".into(),
                enabled: true,
                outbound: vec![],
            },
            AppConfig {
                name: "c".into(),
                binary: "bin_c".into(),
                enabled: false,
                outbound: vec![],
            },
        ],
    };
    let mut state = mock_state_with(config);
    state.handle_exec(1, "bin_a").unwrap();
    state.handle_exec(2, "bin_b").unwrap();
    state.handle_exec(3, "bin_c").unwrap(); // disabled, should be ignored
    assert!(state.status_info().contains("Active apps:    2"));
}

// === status_info with port ranges displayed ===

#[test]
fn status_info_shows_port_range_format() {
    let config = Config {
        base: BaseConfig {
            outbound: vec![],
            icmp: false,
            loopback: false,
        },
        app: vec![AppConfig {
            name: "game".into(),
            binary: "game_bin".into(),
            enabled: true,
            outbound: vec![
                PortRule { port: 27015, range_end: Some(27050), protocol: "udp".into() },
                PortRule { port: 443, range_end: None, protocol: "tcp".into() },
            ],
        }],
    };
    let mut state = mock_state_with(config);
    state.handle_exec(1000, "game_bin").unwrap();

    let status = state.status_info();
    assert!(status.contains("27015-27050/udp"), "Should show range format: {}", status);
    assert!(status.contains("443/tcp"));
}

#[test]
fn status_info_shows_multiple_port_ranges() {
    let config = Config {
        base: BaseConfig {
            outbound: vec![],
            icmp: false,
            loopback: false,
        },
        app: vec![AppConfig {
            name: "complex_app".into(),
            binary: "complex".into(),
            enabled: true,
            outbound: vec![
                PortRule { port: 80, range_end: None, protocol: "tcp".into() },
                PortRule { port: 443, range_end: None, protocol: "tcp".into() },
                PortRule { port: 5000, range_end: Some(6000), protocol: "tcp".into() },
                PortRule { port: 50000, range_end: Some(50100), protocol: "udp".into() },
            ],
        }],
    };
    let mut state = mock_state_with(config);
    state.handle_exec(1000, "complex").unwrap();

    let status = state.status_info();
    assert!(status.contains("80/tcp"));
    assert!(status.contains("443/tcp"));
    assert!(status.contains("5000-6000/tcp"));
    assert!(status.contains("50000-50100/udp"));
}

// === Duplicate PID handling ===

#[test]
fn handle_exec_same_pid_twice_no_panic() {
    let mut state = mock_state();
    state.handle_exec(1000, "Discord").unwrap();
    // Same PID exec again (e.g. PID reuse scenario)
    state.handle_exec(1000, "Discord").unwrap();
    let status = state.status_info();
    // Should still show 1 instance since HashSet deduplicates
    assert!(status.contains("1 instance(s)"));
}

#[test]
fn handle_exit_same_pid_twice_no_panic() {
    let mut state = mock_state();
    state.handle_exec(1000, "Discord").unwrap();
    state.handle_exit(1000, "Discord").unwrap();
    // Second exit of same PID should be a no-op
    state.handle_exit(1000, "Discord").unwrap();
    assert!(state.status_info().contains("Active apps:    0"));
}

// === status_info with no outbound ports ===

#[test]
fn status_info_app_with_no_ports() {
    let config = Config {
        base: BaseConfig {
            outbound: vec![],
            icmp: false,
            loopback: false,
        },
        app: vec![AppConfig {
            name: "noports".into(),
            binary: "noports_bin".into(),
            enabled: true,
            outbound: vec![],
        }],
    };
    let mut state = mock_state_with(config);
    state.handle_exec(1000, "noports_bin").unwrap();
    let status = state.status_info();
    assert!(status.contains("noports"));
    assert!(status.contains("1 instance(s)"));
    // No port arrow lines
    assert!(!status.contains("\u{2192}")); // no arrow character for ports
}

// === Config reference stays consistent ===

#[test]
fn config_stays_consistent_after_exec_exit() {
    let mut state = mock_state();
    let app_count_before = state.config().app.len();
    state.handle_exec(1000, "Discord").unwrap();
    state.handle_exit(1000, "Discord").unwrap();
    assert_eq!(state.config().app.len(), app_count_before);
}

// === Monitored count includes disabled ===

#[test]
fn monitored_count_includes_disabled_apps() {
    let state = mock_state();
    // test_config has 3 apps (discord enabled, firefox enabled, steam disabled)
    let status = state.status_info();
    assert!(status.contains("Monitored apps: 3"));
}

// === Interleaved exec/exit across apps ===

#[test]
fn interleaved_exec_exit_across_apps() {
    let mut state = mock_state();

    state.handle_exec(100, "Discord").unwrap();
    state.handle_exec(200, "firefox").unwrap();
    state.handle_exec(101, "Discord").unwrap();
    state.handle_exit(100, "Discord").unwrap();
    state.handle_exec(201, "firefox").unwrap();
    state.handle_exit(200, "firefox").unwrap();

    let status = state.status_info();
    assert!(status.contains("Active apps:    2"));
    // Discord has 1 remaining instance (101)
    // Firefox has 1 remaining instance (201)
}

// === nft backend called correctly ===

#[test]
fn nft_init_table_callable() {
    let state = mock_state();
    let result = state.nft().init_table(&[], true, true);
    assert!(result.is_ok());
}

#[test]
fn nft_cleanup_callable() {
    let state = mock_state();
    let result = state.nft().cleanup();
    assert!(result.is_ok());
}

// === PID boundary values ===

#[test]
fn handle_exec_pid_zero() {
    let mut state = mock_state();
    state.handle_exec(0, "Discord").unwrap();
    assert!(state.status_info().contains("Active apps:    1"));
    state.handle_exit(0, "Discord").unwrap();
    assert!(state.status_info().contains("Active apps:    0"));
}

#[test]
fn handle_exec_max_u32_pid() {
    let mut state = mock_state();
    state.handle_exec(u32::MAX, "Discord").unwrap();
    assert!(state.status_info().contains("Active apps:    1"));
    assert!(state.status_info().contains(&u32::MAX.to_string()));
}

// === App with empty name/binary edge cases ===

#[test]
fn handle_exec_empty_comm_string() {
    let mut state = mock_state();
    // Empty string won't match any binary
    state.handle_exec(1000, "").unwrap();
    assert!(state.status_info().contains("Active apps:    0"));
}

// === Simultaneous apps full lifecycle ===

#[test]
fn full_lifecycle_three_apps_simultaneous() {
    let mut state = mock_state();

    // Start all enabled apps
    state.handle_exec(100, "Discord").unwrap();
    state.handle_exec(200, "firefox").unwrap();
    assert!(state.status_info().contains("Active apps:    2"));

    // Add more instances
    state.handle_exec(101, "Discord").unwrap();
    state.handle_exec(102, "Discord").unwrap();
    state.handle_exec(201, "firefox").unwrap();

    let status = state.status_info();
    assert!(status.contains("Active apps:    2"));
    assert!(status.contains("3 instance(s)")); // discord

    // Remove all discord instances
    state.handle_exit(100, "Discord").unwrap();
    state.handle_exit(101, "Discord").unwrap();
    state.handle_exit(102, "Discord").unwrap();

    assert!(state.status_info().contains("Active apps:    1"));

    // Remove all firefox instances
    state.handle_exit(200, "firefox").unwrap();
    state.handle_exit(201, "firefox").unwrap();

    assert!(state.status_info().contains("Active apps:    0"));
    assert!(state.status_info().contains("No monitored applications currently running."));
}
