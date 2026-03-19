use clap::Parser;
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

fn main() {
    let cli = Cli::parse();

    match cli {
        Cli::BuildEbpf { release } => build_ebpf(release),
    }
}

fn build_ebpf(release: bool) {
    let mut cmd = Command::new("cargo");
    cmd.current_dir(concat!(env!("CARGO_MANIFEST_DIR"), "/../afw-ebpf"));

    cmd.env_remove("RUSTUP_TOOLCHAIN");
    cmd.args([
        "+nightly",
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
        .expect("Failed to build eBPF programs. Is nightly toolchain installed?");

    if !status.success() {
        eprintln!("eBPF build failed");
        std::process::exit(1);
    }

    println!("eBPF programs built successfully");
}
