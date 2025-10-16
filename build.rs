use std::{env, path::PathBuf, process::Command};

fn main() {
    println!("cargo:rerun-if-env-changed=SKIP_SOLDERING_CLI");
    println!("cargo:rerun-if-env-changed=GSV_SOLDERING_CLI_BUILT");

    if env::var_os("CARGO_FEATURE_SP1_SOLDERING").is_none() {
        return;
    }
    if env::var_os("SKIP_SOLDERING_CLI").is_some() {
        return;
    }
    if env::var_os("GSV_BUILDING_CLI").is_some() {
        return;
    }

    let cargo = env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());

    let mut cmd = Command::new(cargo);
    cmd.args([
        "build",
        "--package",
        "gsv-soldering-core",
        "--bin",
        "gsv-soldering-cli",
        "--release",
    ]);

    let rustflags = env::var("RUSTFLAGS").unwrap_or_default();
    let merged = if rustflags.trim().is_empty() {
        "-C target-cpu=native".to_string()
    } else {
        format!("{rustflags} -C target-cpu=native")
    };
    cmd.env("RUSTFLAGS", merged);
    cmd.env("GSV_BUILDING_CLI", "1");

    let status = cmd
        .status()
        .expect("failed to invoke cargo to build gsv-soldering-cli");

    if !status.success() {
        panic!("building gsv-soldering-cli failed with status {status}");
    }

    let target_dir = env::var_os("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap()).join("target"));

    let exe_suffix = if cfg!(windows) { ".exe" } else { "" };
    let cli_path = target_dir
        .join("release")
        .join(format!("gsv-soldering-cli{exe_suffix}"));

    println!(
        "cargo:rustc-env=GSV_SOLDERING_CLI_BUILT={}",
        cli_path.display()
    );
}
