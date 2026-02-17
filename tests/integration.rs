use std::process::Command;

fn netgrep() -> Command {
    Command::new(env!("CARGO_BIN_EXE_netgrep"))
}

#[test]
fn help_succeeds() {
    let output = netgrep().arg("--help").output().unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Grep for the network"));
}

#[test]
fn version_succeeds() {
    let output = netgrep().arg("--version").output().unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("netgrep"));
}

#[test]
fn conflicting_json_hex_rejected() {
    let output = netgrep().args(["--json", "--hex"]).output().unwrap();
    assert!(!output.status.success());
}

#[test]
fn nonexistent_input_file_fails() {
    let output = netgrep()
        .args(["-I", "/nonexistent/path/file.pcap"])
        .output()
        .unwrap();
    assert!(!output.status.success());
}

#[test]
fn invalid_regex_fails() {
    let output = netgrep().arg("[invalid").output().unwrap();
    assert!(!output.status.success());
}

#[test]
fn output_file_rejects_existing_file() {
    let dir = std::env::temp_dir();
    let path = dir.join("netgrep_test_existing.pcap");

    // Create the file so it already exists
    std::fs::write(&path, b"existing").unwrap();

    // netgrep should refuse to overwrite — needs a valid pcap input too
    // Use a minimal pcap header so the source opens before the output file check
    let pcap_path = dir.join("netgrep_test_input.pcap");
    write_empty_pcap(&pcap_path);

    let output = netgrep()
        .args([
            "-I",
            pcap_path.to_str().unwrap(),
            "-O",
            path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("must not already exist") || stderr.contains("Failed to create"),
        "unexpected stderr: {}",
        stderr,
    );

    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&pcap_path);
}

#[test]
fn empty_pcap_reads_without_panic() {
    let dir = std::env::temp_dir();
    let path = dir.join("netgrep_test_empty.pcap");
    write_empty_pcap(&path);

    let output = netgrep()
        .args(["-I", path.to_str().unwrap(), "test"])
        .output()
        .unwrap();

    // Should succeed (0 matches, no panic)
    assert!(output.status.success());

    let _ = std::fs::remove_file(&path);
}

#[test]
fn count_flag_validates_range() {
    // 0 is below the minimum (1)
    let output = netgrep().args(["-n", "0"]).output().unwrap();
    assert!(!output.status.success());
}

#[test]
fn invert_without_pattern_warns() {
    let dir = std::env::temp_dir();
    let path = dir.join("netgrep_test_invert.pcap");
    write_empty_pcap(&path);

    let output = netgrep()
        .args(["-v", "-I", path.to_str().unwrap()])
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("invert with no pattern"));

    let _ = std::fs::remove_file(&path);
}

/// Write a minimal valid pcap file (header only, no packets).
fn write_empty_pcap(path: &std::path::Path) {
    let mut header = Vec::with_capacity(24);
    header.extend_from_slice(&0xa1b2c3d4u32.to_le_bytes()); // magic
    header.extend_from_slice(&2u16.to_le_bytes()); // major version
    header.extend_from_slice(&4u16.to_le_bytes()); // minor version
    header.extend_from_slice(&0i32.to_le_bytes()); // thiszone
    header.extend_from_slice(&0u32.to_le_bytes()); // sigfigs
    header.extend_from_slice(&65535u32.to_le_bytes()); // snaplen
    header.extend_from_slice(&1u32.to_le_bytes()); // network (Ethernet)
    std::fs::write(path, &header).unwrap();
}
