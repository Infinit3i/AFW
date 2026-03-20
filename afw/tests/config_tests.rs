use afw::config::*;

// === Helpers ===

fn sample_config() -> Config {
    Config {
        base: BaseConfig {
            outbound: vec![
                PortRule { port: 53, range_end: None, protocol: "udp".into() },
                PortRule { port: 443, range_end: None, protocol: "tcp".into() },
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
                    PortRule { port: 50000, range_end: Some(50100), protocol: "udp".into() },
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
            AppConfig {
                name: "firefox".into(),
                binary: "firefox".into(),
                enabled: true,
                outbound: vec![
                    PortRule { port: 80, range_end: None, protocol: "tcp".into() },
                ],
            },
        ],
    }
}

// === parse_port_rule ===

#[test]
fn parse_single_tcp_port() {
    let rule = parse_port_rule("443/tcp").unwrap();
    assert_eq!(rule.port, 443);
    assert_eq!(rule.range_end, None);
    assert_eq!(rule.protocol, "tcp");
}

#[test]
fn parse_single_udp_port() {
    let rule = parse_port_rule("53/udp").unwrap();
    assert_eq!(rule.port, 53);
    assert_eq!(rule.range_end, None);
    assert_eq!(rule.protocol, "udp");
}

#[test]
fn parse_port_range() {
    let rule = parse_port_rule("50000-50100/udp").unwrap();
    assert_eq!(rule.port, 50000);
    assert_eq!(rule.range_end, Some(50100));
    assert_eq!(rule.protocol, "udp");
}

#[test]
fn parse_port_case_insensitive_protocol() {
    let rule = parse_port_rule("80/TCP").unwrap();
    assert_eq!(rule.protocol, "tcp");
}

#[test]
fn parse_port_invalid_no_protocol() {
    assert!(parse_port_rule("443").is_err());
}

#[test]
fn parse_port_invalid_protocol() {
    assert!(parse_port_rule("443/sctp").is_err());
}

#[test]
fn parse_port_invalid_number() {
    assert!(parse_port_rule("abc/tcp").is_err());
}

#[test]
fn parse_port_range_end_less_than_start() {
    assert!(parse_port_rule("50100-50000/udp").is_err());
}

#[test]
fn parse_port_range_equal() {
    assert!(parse_port_rule("50000-50000/udp").is_err());
}

#[test]
fn parse_port_empty_string() {
    assert!(parse_port_rule("").is_err());
}

#[test]
fn parse_port_multiple_slashes() {
    assert!(parse_port_rule("443/tcp/extra").is_err());
}

#[test]
fn parse_port_overflow() {
    assert!(parse_port_rule("99999/tcp").is_err());
}

#[test]
fn parse_port_boundary_min() {
    let rule = parse_port_rule("1/tcp").unwrap();
    assert_eq!(rule.port, 1);
}

#[test]
fn parse_port_boundary_max() {
    let rule = parse_port_rule("65535/tcp").unwrap();
    assert_eq!(rule.port, 65535);
}

#[test]
fn parse_port_zero() {
    // Port 0 is technically valid as a u16 parse but unusual
    let rule = parse_port_rule("0/tcp").unwrap();
    assert_eq!(rule.port, 0);
}

// === Config deserialization ===

#[test]
fn deserialize_full_config() {
    let toml_str = r#"
[base]
outbound = [
    { port = 53, protocol = "udp" },
    { port = 443, protocol = "tcp" },
]
icmp = true
loopback = true

[[app]]
name = "discord"
binary = "Discord"
enabled = true
outbound = [
    { port = 443, protocol = "tcp" },
    { port = 50000, range_end = 50100, protocol = "udp" },
]
"#;
    let config: Config = toml::from_str(toml_str).unwrap();
    assert_eq!(config.base.outbound.len(), 2);
    assert!(config.base.icmp);
    assert!(config.base.loopback);
    assert_eq!(config.app.len(), 1);
    assert_eq!(config.app[0].name, "discord");
    assert_eq!(config.app[0].binary, "Discord");
    assert_eq!(config.app[0].outbound.len(), 2);
    assert_eq!(config.app[0].outbound[1].range_end, Some(50100));
}

#[test]
fn deserialize_minimal_config() {
    let toml_str = "[base]\n";
    let config: Config = toml::from_str(toml_str).unwrap();
    assert_eq!(config.base.outbound.len(), 5); // default_base_ports
    assert!(config.base.icmp);
    assert!(config.base.loopback);
    assert!(config.app.is_empty());
}

#[test]
fn deserialize_app_defaults_enabled() {
    let toml_str = r#"
[base]
outbound = []

[[app]]
name = "test"
binary = "test_bin"
outbound = []
"#;
    let config: Config = toml::from_str(toml_str).unwrap();
    assert!(config.app[0].enabled);
}

#[test]
fn deserialize_base_defaults_icmp_and_loopback() {
    let toml_str = r#"
[base]
outbound = []
"#;
    let config: Config = toml::from_str(toml_str).unwrap();
    assert!(config.base.icmp);
    assert!(config.base.loopback);
}

#[test]
fn deserialize_disabled_features() {
    let toml_str = r#"
[base]
outbound = []
icmp = false
loopback = false
"#;
    let config: Config = toml::from_str(toml_str).unwrap();
    assert!(!config.base.icmp);
    assert!(!config.base.loopback);
}

#[test]
fn deserialize_multiple_apps() {
    let toml_str = r#"
[base]
outbound = []

[[app]]
name = "app1"
binary = "bin1"
outbound = [{ port = 80, protocol = "tcp" }]

[[app]]
name = "app2"
binary = "bin2"
enabled = false
outbound = [{ port = 443, protocol = "tcp" }]
"#;
    let config: Config = toml::from_str(toml_str).unwrap();
    assert_eq!(config.app.len(), 2);
    assert!(config.app[0].enabled);
    assert!(!config.app[1].enabled);
}

// === Config serialization roundtrip ===

#[test]
fn config_roundtrip_serialization() {
    let config = sample_config();
    let serialized = toml::to_string_pretty(&config).unwrap();
    let deserialized: Config = toml::from_str(&serialized).unwrap();
    assert_eq!(deserialized.base.outbound.len(), config.base.outbound.len());
    assert_eq!(deserialized.app.len(), config.app.len());
    assert_eq!(deserialized.app[0].name, "discord");
    assert_eq!(deserialized.app[1].enabled, false);
}

// === find_app_by_binary ===

#[test]
fn find_app_by_binary_found() {
    let config = sample_config();
    let app = config.find_app_by_binary("Discord").unwrap();
    assert_eq!(app.name, "discord");
}

#[test]
fn find_app_by_binary_not_found() {
    let config = sample_config();
    assert!(config.find_app_by_binary("nonexistent").is_none());
}

#[test]
fn find_app_by_binary_skips_disabled() {
    let config = sample_config();
    assert!(config.find_app_by_binary("steam").is_none());
}

#[test]
fn find_app_by_binary_case_sensitive() {
    let config = sample_config();
    assert!(config.find_app_by_binary("discord").is_none()); // "Discord" not "discord"
    assert!(config.find_app_by_binary("Discord").is_some());
}

// === find_app_by_name ===

#[test]
fn find_app_by_name_found() {
    let config = sample_config();
    let app = config.find_app_by_name("discord").unwrap();
    assert_eq!(app.binary, "Discord");
}

#[test]
fn find_app_by_name_finds_disabled() {
    let config = sample_config();
    let app = config.find_app_by_name("steam").unwrap();
    assert_eq!(app.binary, "steam");
}

#[test]
fn find_app_by_name_not_found() {
    let config = sample_config();
    assert!(config.find_app_by_name("nonexistent").is_none());
}

// === binary_to_app_map ===

#[test]
fn binary_to_app_map_enabled_only() {
    let config = sample_config();
    let map = config.binary_to_app_map();
    assert!(map.contains_key("Discord"));
    assert!(map.contains_key("firefox"));
    assert!(!map.contains_key("steam"));
    assert_eq!(map.len(), 2);
}

#[test]
fn binary_to_app_map_empty_config() {
    let config = Config {
        base: BaseConfig {
            outbound: vec![],
            icmp: false,
            loopback: false,
        },
        app: vec![],
    };
    let map = config.binary_to_app_map();
    assert!(map.is_empty());
}

#[test]
fn binary_to_app_map_all_disabled() {
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
    let map = config.binary_to_app_map();
    assert!(map.is_empty());
}

// === Config save/load with temp files ===

#[test]
fn config_save_and_load() {
    let config = sample_config();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("test_afw.toml");
    let path_str = path.to_str().unwrap();

    config.save(Some(path_str)).unwrap();
    let loaded = Config::load(Some(path_str)).unwrap();

    assert_eq!(loaded.base.outbound.len(), config.base.outbound.len());
    assert_eq!(loaded.base.icmp, config.base.icmp);
    assert_eq!(loaded.app.len(), config.app.len());
    for (orig, loaded) in config.app.iter().zip(loaded.app.iter()) {
        assert_eq!(orig.name, loaded.name);
        assert_eq!(orig.binary, loaded.binary);
        assert_eq!(orig.enabled, loaded.enabled);
        assert_eq!(orig.outbound.len(), loaded.outbound.len());
    }
}

#[test]
fn config_load_nonexistent() {
    assert!(Config::load(Some("/tmp/nonexistent_afw_test_12345.toml")).is_err());
}

#[test]
fn config_load_invalid_toml() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("bad.toml");
    std::fs::write(&path, "this is not valid toml [[[").unwrap();
    assert!(Config::load(Some(path.to_str().unwrap())).is_err());
}

#[test]
fn config_save_creates_parent_dirs() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("nested").join("deep").join("afw.toml");
    let config = sample_config();
    config.save(Some(path.to_str().unwrap())).unwrap();
    assert!(path.exists());
}

#[test]
fn config_load_real_example() {
    // Test loading the actual example config file + conf.d drop-ins
    let config = Config::load(Some(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../config/afw.toml"
    )));
    let config = config.unwrap();
    assert_eq!(config.base.outbound.len(), 15);
    assert!(config.base.icmp);
    assert!(config.base.loopback);
    // Apps come from conf.d/ drop-in files
    assert!(config.app.len() >= 3);
    // Verify some apps from different drop-in files are loaded
    assert!(config.find_app_by_name("discord").is_some());
    assert!(config.find_app_by_name("firefox").is_some());
    assert!(config.find_app_by_name("steam").is_some());
    assert!(config.find_app_by_name("wireguard").is_some());
    assert!(config.find_app_by_name("spotify").is_some());
}

// === Drop-in config tests ===

#[test]
fn load_with_conf_d_directory() {
    let dir = tempfile::tempdir().unwrap();
    let conf_d = dir.path().join("conf.d");
    std::fs::create_dir_all(&conf_d).unwrap();

    // Write main config (base only)
    let main_path = dir.path().join("afw.toml");
    std::fs::write(&main_path, r#"
[base]
outbound = [{ port = 53, protocol = "udp" }]
"#).unwrap();

    // Write a drop-in
    std::fs::write(conf_d.join("browsers.toml"), r#"
[[app]]
name = "firefox"
binary = "firefox"
outbound = [{ port = 443, protocol = "tcp" }]
"#).unwrap();

    // Write another drop-in
    std::fs::write(conf_d.join("gaming.toml"), r#"
[[app]]
name = "steam"
binary = "steam"
outbound = [{ port = 80, protocol = "tcp" }]
"#).unwrap();

    let config = Config::load(Some(main_path.to_str().unwrap())).unwrap();
    assert_eq!(config.base.outbound.len(), 1);
    assert_eq!(config.app.len(), 2);
    assert!(config.find_app_by_name("firefox").is_some());
    assert!(config.find_app_by_name("steam").is_some());
}

#[test]
fn load_without_conf_d_directory() {
    let dir = tempfile::tempdir().unwrap();
    let main_path = dir.path().join("afw.toml");
    std::fs::write(&main_path, r#"
[base]
outbound = []

[[app]]
name = "test"
binary = "test"
outbound = []
"#).unwrap();

    // No conf.d/ directory — should still work fine
    let config = Config::load(Some(main_path.to_str().unwrap())).unwrap();
    assert_eq!(config.app.len(), 1);
}

#[test]
fn drop_ins_loaded_alphabetically() {
    let dir = tempfile::tempdir().unwrap();
    let conf_d = dir.path().join("conf.d");
    std::fs::create_dir_all(&conf_d).unwrap();

    let main_path = dir.path().join("afw.toml");
    std::fs::write(&main_path, "[base]\noutbound = []\n").unwrap();

    std::fs::write(conf_d.join("b_second.toml"), r#"
[[app]]
name = "bravo"
binary = "bravo"
outbound = []
"#).unwrap();

    std::fs::write(conf_d.join("a_first.toml"), r#"
[[app]]
name = "alpha"
binary = "alpha"
outbound = []
"#).unwrap();

    let config = Config::load(Some(main_path.to_str().unwrap())).unwrap();
    assert_eq!(config.app[0].name, "alpha");
    assert_eq!(config.app[1].name, "bravo");
}

#[test]
fn non_toml_files_in_conf_d_ignored() {
    let dir = tempfile::tempdir().unwrap();
    let conf_d = dir.path().join("conf.d");
    std::fs::create_dir_all(&conf_d).unwrap();

    let main_path = dir.path().join("afw.toml");
    std::fs::write(&main_path, "[base]\noutbound = []\n").unwrap();

    std::fs::write(conf_d.join("valid.toml"), r#"
[[app]]
name = "valid"
binary = "valid"
outbound = []
"#).unwrap();

    std::fs::write(conf_d.join("readme.md"), "# Not a config").unwrap();
    std::fs::write(conf_d.join("backup.bak"), "junk").unwrap();

    let config = Config::load(Some(main_path.to_str().unwrap())).unwrap();
    assert_eq!(config.app.len(), 1);
    assert_eq!(config.app[0].name, "valid");
}

#[test]
fn save_apps_to_drop_in() {
    let dir = tempfile::tempdir().unwrap();
    let main_path = dir.path().join("afw.toml");
    std::fs::write(&main_path, "[base]\noutbound = []\n").unwrap();

    let apps = vec![
        AppConfig {
            name: "test_vpn".into(),
            binary: "vpn_bin".into(),
            enabled: true,
            outbound: vec![PortRule { port: 1194, range_end: None, protocol: "udp".into() }],
        },
    ];

    Config::save_apps_to_drop_in(&apps, "vpn_clients", Some(main_path.to_str().unwrap())).unwrap();

    let drop_in_path = dir.path().join("conf.d").join("vpn_clients.toml");
    assert!(drop_in_path.exists());

    // Now load and verify it merges
    let config = Config::load(Some(main_path.to_str().unwrap())).unwrap();
    assert_eq!(config.app.len(), 1);
    assert_eq!(config.app[0].name, "test_vpn");
}

#[test]
fn main_config_apps_merge_with_drop_ins() {
    let dir = tempfile::tempdir().unwrap();
    let conf_d = dir.path().join("conf.d");
    std::fs::create_dir_all(&conf_d).unwrap();

    let main_path = dir.path().join("afw.toml");
    std::fs::write(&main_path, r#"
[base]
outbound = []

[[app]]
name = "inline_app"
binary = "inline"
outbound = []
"#).unwrap();

    std::fs::write(conf_d.join("extra.toml"), r#"
[[app]]
name = "dropin_app"
binary = "dropin"
outbound = []
"#).unwrap();

    let config = Config::load(Some(main_path.to_str().unwrap())).unwrap();
    assert_eq!(config.app.len(), 2);
    assert!(config.find_app_by_name("inline_app").is_some());
    assert!(config.find_app_by_name("dropin_app").is_some());
}
