use clap::Parser;
use std::path::PathBuf;
use std::process::Command;

#[derive(Parser)]
enum Cli {
    /// Build the eBPF programs
    BuildEbpf {
        /// Build in release mode
        #[clap(long)]
        release: bool,
    },
}

fn find_rustup() -> PathBuf {
    // Try PATH first
    if let Ok(output) = Command::new("which").arg("rustup").output() {
        if output.status.success() {
            let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !path.is_empty() {
                return PathBuf::from(path);
            }
        }
    }
    // Fall back to ~/.cargo/bin/rustup
    if let Some(home) = std::env::var_os("HOME") {
        let candidate = PathBuf::from(home).join(".cargo/bin/rustup");
        if candidate.exists() {
            return candidate;
        }
    }
    // Last resort
    PathBuf::from("rustup")
}

fn main() {
    let cli = Cli::parse();

    match cli {
        Cli::BuildEbpf { release } => build_ebpf(release),
    }
}

fn build_ebpf(release: bool) {
    let rustup = find_rustup();
    let mut cmd = Command::new(&rustup);
    cmd.current_dir(concat!(env!("CARGO_MANIFEST_DIR"), "/../afw-ebpf"));

    cmd.env_remove("RUSTUP_TOOLCHAIN");
    cmd.args([
        "run",
        "nightly",
        "cargo",
        "build",
        "--target=bpfel-unknown-none",
        "-Z",
        "build-std=core",
    ]);

    if release {
        cmd.arg("--release");
    }

    let status = cmd
        .status()
        .unwrap_or_else(|e| panic!(
            "Failed to run rustup at {:?}: {}. Is rustup installed and in PATH?",
            rustup, e
        ));

    if !status.success() {
        eprintln!("eBPF build failed");
        std::process::exit(1);
    }

    println!("eBPF programs built successfully");
}
