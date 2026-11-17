//! The binary's command line and configuration checks (the daemon itself
//! is tested end to end with the API, in `kernel/api/tests`).

#![cfg(target_os = "linux")]

use std::process::Command;

fn noded(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_hellovm-noded"))
        .args(args)
        .output()
        .unwrap()
}

#[test]
fn bad_command_lines_and_configs_are_refused() {
    assert_eq!(noded(&[]).status.code(), Some(2));
    assert_eq!(noded(&["--config"]).status.code(), Some(2));
    let missing = noded(&["--config", "/nonexistent/noded.json"]);
    assert_eq!(missing.status.code(), Some(1));
    let dir = std::env::temp_dir().join(format!("noded-cli-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let config = dir.join("noded.json");
    // A shared template may not drop the Landlock requirement.
    std::fs::write(
        &config,
        r#"{"node":"n","listen":"127.0.0.1:0","token":"0123456789abcdef0123456789",
            "hellovm":"/bin/true","state_dir":"/tmp/x",
            "templates":[{"name":"p","root":"/","sandbox":"best-effort"}]}"#,
    )
    .unwrap();
    let out = noded(&["--config", config.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("must run with --sandbox require"),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    std::fs::remove_dir_all(&dir).unwrap();
}
