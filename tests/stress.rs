//! Aggressive stress tests for pre-release validation.
//! Targets protocol parsers, reassembly engine, and CLI edge cases
//! with malformed, boundary, and adversarial inputs.

use std::path::Path;
use std::process::Command;

fn netgrep() -> Command {
    Command::new(env!("CARGO_BIN_EXE_netgrep"))
}

// =============================================================================
// Pcap helpers (duplicated from integration.rs for independence)
// =============================================================================

fn write_empty_pcap(path: &Path) {
    let mut header = Vec::with_capacity(24);
    header.extend_from_slice(&0xa1b2c3d4u32.to_le_bytes());
    header.extend_from_slice(&2u16.to_le_bytes());
    header.extend_from_slice(&4u16.to_le_bytes());
    header.extend_from_slice(&0i32.to_le_bytes());
    header.extend_from_slice(&0u32.to_le_bytes());
    header.extend_from_slice(&65535u32.to_le_bytes());
    header.extend_from_slice(&1u32.to_le_bytes());
    std::fs::write(path, &header).unwrap();
}

fn build_eth_tcp_packet(
    src_ip: [u8; 4],
    dst_ip: [u8; 4],
    src_port: u16,
    dst_port: u16,
    seq: u32,
    flags_byte: u8,
    payload: &[u8],
) -> Vec<u8> {
    use etherparse::PacketBuilder;
    let builder = PacketBuilder::ethernet2([0; 6], [0; 6])
        .ipv4(src_ip, dst_ip, 64)
        .tcp(src_port, dst_port, seq, 65535);
    let mut buf = Vec::new();
    builder.write(&mut buf, payload).unwrap();
    buf[14 + 20 + 13] = flags_byte;
    buf
}

fn build_eth_udp_packet(
    src_ip: [u8; 4],
    dst_ip: [u8; 4],
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    use etherparse::PacketBuilder;
    let builder = PacketBuilder::ethernet2([0; 6], [0; 6])
        .ipv4(src_ip, dst_ip, 64)
        .udp(src_port, dst_port);
    let mut buf = Vec::new();
    builder.write(&mut buf, payload).unwrap();
    buf
}

fn write_pcap(path: &Path, packets: &[(&[u8], u32, u32)]) {
    let mut data = Vec::new();
    data.extend_from_slice(&0xa1b2c3d4u32.to_le_bytes());
    data.extend_from_slice(&2u16.to_le_bytes());
    data.extend_from_slice(&4u16.to_le_bytes());
    data.extend_from_slice(&0i32.to_le_bytes());
    data.extend_from_slice(&0u32.to_le_bytes());
    data.extend_from_slice(&65535u32.to_le_bytes());
    data.extend_from_slice(&1u32.to_le_bytes());
    for &(pkt, ts_sec, ts_usec) in packets {
        let len = pkt.len() as u32;
        data.extend_from_slice(&ts_sec.to_le_bytes());
        data.extend_from_slice(&ts_usec.to_le_bytes());
        data.extend_from_slice(&len.to_le_bytes());
        data.extend_from_slice(&len.to_le_bytes());
        data.extend_from_slice(pkt);
    }
    std::fs::write(path, &data).unwrap();
}

fn build_tcp_stream(
    src_ip: [u8; 4],
    dst_ip: [u8; 4],
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Vec<(Vec<u8>, u32, u32)> {
    let syn = build_eth_tcp_packet(src_ip, dst_ip, src_port, dst_port, 100, 0x02, &[]);
    let syn_ack = build_eth_tcp_packet(dst_ip, src_ip, dst_port, src_port, 200, 0x12, &[]);
    let psh_ack = build_eth_tcp_packet(src_ip, dst_ip, src_port, dst_port, 101, 0x18, payload);
    vec![(syn, 1000, 0), (syn_ack, 1000, 1000), (psh_ack, 1000, 2000)]
}

fn temp_pcap(name: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!(
        "netgrep_stress_{}_{}.pcap",
        name,
        std::process::id()
    ))
}

// =============================================================================
// CLI edge cases
// =============================================================================

#[test]
fn cli_empty_pattern_string() {
    // Empty string pattern should match everything (regex "")
    let path = temp_pcap("empty_pattern");
    let packets = build_tcp_stream([10, 0, 0, 1], [10, 0, 0, 2], 1234, 80, b"data");
    let refs: Vec<(&[u8], u32, u32)> = packets
        .iter()
        .map(|(d, s, u)| (d.as_slice(), *s, *u))
        .collect();
    write_pcap(&path, &refs);

    let output = netgrep()
        .args(["-I", path.to_str().unwrap(), ""])
        .output()
        .unwrap();
    assert!(output.status.success());
    let _ = std::fs::remove_file(&path);
}

#[test]
fn cli_max_count_boundary() {
    // Test max count value (1048576)
    let path = temp_pcap("max_count");
    write_empty_pcap(&path);
    let output = netgrep()
        .args(["-I", path.to_str().unwrap(), "-n", "1048576"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let _ = std::fs::remove_file(&path);
}

#[test]
fn cli_count_above_max_rejected() {
    let output = netgrep().args(["-n", "1048577"]).output().unwrap();
    assert!(!output.status.success());
}

#[test]
fn cli_snaplen_boundary_min() {
    let path = temp_pcap("snaplen_min");
    write_empty_pcap(&path);
    let output = netgrep()
        .args(["-I", path.to_str().unwrap(), "-s", "1"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let _ = std::fs::remove_file(&path);
}

#[test]
fn cli_snaplen_boundary_max() {
    let path = temp_pcap("snaplen_max");
    write_empty_pcap(&path);
    let output = netgrep()
        .args(["-I", path.to_str().unwrap(), "-s", "65535"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let _ = std::fs::remove_file(&path);
}

#[test]
fn cli_snaplen_zero_rejected() {
    let output = netgrep().args(["-s", "0"]).output().unwrap();
    assert!(!output.status.success());
}

#[test]
fn cli_snaplen_above_max_rejected() {
    let output = netgrep().args(["-s", "65536"]).output().unwrap();
    assert!(!output.status.success());
}

#[test]
fn cli_all_modes_combined() {
    // --http --dns together on a regular TCP stream — should not crash
    let path = temp_pcap("all_modes");
    let packets = build_tcp_stream(
        [10, 0, 0, 1],
        [10, 0, 0, 2],
        1234,
        80,
        b"GET / HTTP/1.1\r\nHost: x\r\n\r\n",
    );
    let refs: Vec<(&[u8], u32, u32)> = packets
        .iter()
        .map(|(d, s, u)| (d.as_slice(), *s, *u))
        .collect();
    write_pcap(&path, &refs);

    let output = netgrep()
        .args(["-I", path.to_str().unwrap(), "--http", "--dns"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let _ = std::fs::remove_file(&path);
}

#[test]
fn cli_json_quiet_combined() {
    // --json and --quiet together
    let path = temp_pcap("json_quiet");
    let packets = build_tcp_stream([10, 0, 0, 1], [10, 0, 0, 2], 1234, 80, b"payload");
    let refs: Vec<(&[u8], u32, u32)> = packets
        .iter()
        .map(|(d, s, u)| (d.as_slice(), *s, *u))
        .collect();
    write_pcap(&path, &refs);

    let output = netgrep()
        .args(["-I", path.to_str().unwrap(), "--json", "-q"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    // Should still be valid JSON
    for line in stdout.lines() {
        if !line.trim().is_empty() {
            assert!(
                serde_json::from_str::<serde_json::Value>(line).is_ok(),
                "Invalid JSON: {}",
                line
            );
        }
    }
    let _ = std::fs::remove_file(&path);
}

#[test]
fn cli_negative_count_rejected() {
    let output = netgrep().args(["-n", "-1"]).output().unwrap();
    assert!(!output.status.success());
}

#[test]
fn cli_nonexistent_keylog_file() {
    let path = temp_pcap("keylog_missing");
    write_empty_pcap(&path);
    let output = netgrep()
        .args([
            "-I",
            path.to_str().unwrap(),
            "--keylog",
            "/nonexistent/keylog.txt",
        ])
        .output()
        .unwrap();
    // Should fail gracefully, not panic
    assert!(!output.status.success());
    let _ = std::fs::remove_file(&path);
}

#[test]
fn cli_invalid_bpf_filter() {
    let path = temp_pcap("bad_bpf");
    write_empty_pcap(&path);
    let output = netgrep()
        .args([
            "-I",
            path.to_str().unwrap(),
            "-F",
            "not a valid bpf at all!!!",
        ])
        .output()
        .unwrap();
    assert!(!output.status.success());
    let _ = std::fs::remove_file(&path);
}

#[test]
fn cli_catastrophic_regex_rejected() {
    // This regex would cause exponential backtracking in naive engines.
    // Rust's regex crate handles this safely, but verify it doesn't hang.
    let path = temp_pcap("regex_bomb");
    let packets = build_tcp_stream(
        [10, 0, 0, 1],
        [10, 0, 0, 2],
        1234,
        80,
        b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    );
    let refs: Vec<(&[u8], u32, u32)> = packets
        .iter()
        .map(|(d, s, u)| (d.as_slice(), *s, *u))
        .collect();
    write_pcap(&path, &refs);

    let output = netgrep()
        .args([
            "-I",
            path.to_str().unwrap(),
            "(a+)+$", // classic ReDoS pattern — safe in Rust regex
        ])
        .output()
        .unwrap();
    // Should complete (not hang) — Rust regex is linear time
    assert!(output.status.success());
    let _ = std::fs::remove_file(&path);
}

#[test]
fn cli_no_reassemble_with_http_flag() {
    // --http with --no-reassemble: HTTP parsing requires stream data,
    // so this should just show packets without HTTP parsing
    let path = temp_pcap("no_reassemble_http");
    let packets = build_tcp_stream(
        [10, 0, 0, 1],
        [10, 0, 0, 2],
        1234,
        80,
        b"GET / HTTP/1.1\r\nHost: x\r\n\r\n",
    );
    let refs: Vec<(&[u8], u32, u32)> = packets
        .iter()
        .map(|(d, s, u)| (d.as_slice(), *s, *u))
        .collect();
    write_pcap(&path, &refs);

    let output = netgrep()
        .args(["-I", path.to_str().unwrap(), "--http", "--no-reassemble"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let _ = std::fs::remove_file(&path);
}

#[test]
fn cli_output_file_to_dev_null_like_path() {
    // -O to a path inside a nonexistent directory should fail gracefully
    let path = temp_pcap("output_bad_dir");
    write_empty_pcap(&path);
    let output = netgrep()
        .args([
            "-I",
            path.to_str().unwrap(),
            "-O",
            "/nonexistent_dir/output.pcap",
        ])
        .output()
        .unwrap();
    assert!(!output.status.success());
    let _ = std::fs::remove_file(&path);
}

#[test]
fn cli_line_buffered_works() {
    let path = temp_pcap("line_buffered");
    let packets = build_tcp_stream([10, 0, 0, 1], [10, 0, 0, 2], 1234, 80, b"buffered");
    let refs: Vec<(&[u8], u32, u32)> = packets
        .iter()
        .map(|(d, s, u)| (d.as_slice(), *s, *u))
        .collect();
    write_pcap(&path, &refs);

    let output = netgrep()
        .args(["-I", path.to_str().unwrap(), "-l"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let _ = std::fs::remove_file(&path);
}

// =============================================================================
// Malformed packet handling (should never panic)
// =============================================================================

#[test]
fn truncated_pcap_header() {
    let path = temp_pcap("truncated_header");
    // Write only 12 bytes of the 24-byte pcap header
    std::fs::write(
        &path,
        &[0xd4, 0xc3, 0xb2, 0xa1, 0x02, 0x00, 0x04, 0x00, 0, 0, 0, 0],
    )
    .unwrap();
    let output = netgrep()
        .args(["-I", path.to_str().unwrap()])
        .output()
        .unwrap();
    // Should fail gracefully
    assert!(!output.status.success());
    let _ = std::fs::remove_file(&path);
}

#[test]
fn pcap_with_zero_length_packet() {
    let path = temp_pcap("zero_len_pkt");
    let mut data = Vec::new();
    // Valid pcap header
    data.extend_from_slice(&0xa1b2c3d4u32.to_le_bytes());
    data.extend_from_slice(&2u16.to_le_bytes());
    data.extend_from_slice(&4u16.to_le_bytes());
    data.extend_from_slice(&0i32.to_le_bytes());
    data.extend_from_slice(&0u32.to_le_bytes());
    data.extend_from_slice(&65535u32.to_le_bytes());
    data.extend_from_slice(&1u32.to_le_bytes());
    // Packet header with 0 length
    data.extend_from_slice(&1000u32.to_le_bytes()); // ts_sec
    data.extend_from_slice(&0u32.to_le_bytes()); // ts_usec
    data.extend_from_slice(&0u32.to_le_bytes()); // incl_len = 0
    data.extend_from_slice(&0u32.to_le_bytes()); // orig_len = 0
    std::fs::write(&path, &data).unwrap();

    let output = netgrep()
        .args(["-I", path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(output.status.success());
    let _ = std::fs::remove_file(&path);
}

#[test]
fn binary_payload_no_crash() {
    // Full binary payload (all byte values 0x00-0xFF)
    let path = temp_pcap("binary_payload");
    let payload: Vec<u8> = (0..=255u8).collect();
    let packets = build_tcp_stream([10, 0, 0, 1], [10, 0, 0, 2], 1234, 80, &payload);
    let refs: Vec<(&[u8], u32, u32)> = packets
        .iter()
        .map(|(d, s, u)| (d.as_slice(), *s, *u))
        .collect();
    write_pcap(&path, &refs);

    let output = netgrep()
        .args(["-I", path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(output.status.success());
    let _ = std::fs::remove_file(&path);
}

#[test]
fn binary_payload_hex_output() {
    let path = temp_pcap("binary_hex");
    let payload: Vec<u8> = (0..=255u8).collect();
    let packets = build_tcp_stream([10, 0, 0, 1], [10, 0, 0, 2], 1234, 80, &payload);
    let refs: Vec<(&[u8], u32, u32)> = packets
        .iter()
        .map(|(d, s, u)| (d.as_slice(), *s, *u))
        .collect();
    write_pcap(&path, &refs);

    let output = netgrep()
        .args(["-I", path.to_str().unwrap(), "-x"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    // Should contain hex dump with all bytes
    assert!(stdout.contains("00000000"));
    let _ = std::fs::remove_file(&path);
}

#[test]
fn binary_payload_json_output() {
    let path = temp_pcap("binary_json");
    let payload: Vec<u8> = (0..=255u8).collect();
    let packets = build_tcp_stream([10, 0, 0, 1], [10, 0, 0, 2], 1234, 80, &payload);
    let refs: Vec<(&[u8], u32, u32)> = packets
        .iter()
        .map(|(d, s, u)| (d.as_slice(), *s, *u))
        .collect();
    write_pcap(&path, &refs);

    let output = netgrep()
        .args(["-I", path.to_str().unwrap(), "--json"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in stdout.lines() {
        if !line.trim().is_empty() {
            assert!(
                serde_json::from_str::<serde_json::Value>(line).is_ok(),
                "Binary payload produced invalid JSON"
            );
        }
    }
    let _ = std::fs::remove_file(&path);
}

#[test]
fn terminal_escape_sequences_in_payload() {
    // Test that ANSI escape sequences in payload don't leak to terminal
    let path = temp_pcap("escape_seq");
    let evil_payload = b"\x1b[31mRED\x1b[0m\x1b]0;EVIL_TITLE\x07\x1b[2J";
    let packets = build_tcp_stream([10, 0, 0, 1], [10, 0, 0, 2], 1234, 80, evil_payload);
    let refs: Vec<(&[u8], u32, u32)> = packets
        .iter()
        .map(|(d, s, u)| (d.as_slice(), *s, *u))
        .collect();
    write_pcap(&path, &refs);

    let output = netgrep()
        .args(["-I", path.to_str().unwrap()])
        .env("NO_COLOR", "1")
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    // The raw escape byte \x1b should be sanitized
    assert!(
        !stdout.contains('\x1b'),
        "Escape sequences leaked to output: {:?}",
        stdout
    );
    let _ = std::fs::remove_file(&path);
}

#[test]
fn null_bytes_in_payload() {
    let path = temp_pcap("null_bytes");
    let payload = b"before\x00after\x00\x00end";
    let packets = build_tcp_stream([10, 0, 0, 1], [10, 0, 0, 2], 1234, 80, payload);
    let refs: Vec<(&[u8], u32, u32)> = packets
        .iter()
        .map(|(d, s, u)| (d.as_slice(), *s, *u))
        .collect();
    write_pcap(&path, &refs);

    let output = netgrep()
        .args(["-I", path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(output.status.success());
    let _ = std::fs::remove_file(&path);
}

// =============================================================================
// HTTP parser stress tests
// =============================================================================

#[test]
fn http_malformed_request_line() {
    let path = temp_pcap("http_malformed");
    let payload = b"NOTAMETHOD /path\r\n\r\n";
    let packets = build_tcp_stream([10, 0, 0, 1], [10, 0, 0, 2], 1234, 80, payload);
    let refs: Vec<(&[u8], u32, u32)> = packets
        .iter()
        .map(|(d, s, u)| (d.as_slice(), *s, *u))
        .collect();
    write_pcap(&path, &refs);

    let output = netgrep()
        .args(["-I", path.to_str().unwrap(), "--http"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let _ = std::fs::remove_file(&path);
}

#[test]
fn http_enormous_header_count() {
    // 300 headers (above MAX_HEADERS=200 limit)
    let path = temp_pcap("http_many_headers");
    let mut payload = b"GET / HTTP/1.1\r\n".to_vec();
    for i in 0..300 {
        payload.extend_from_slice(format!("X-Header-{}: value{}\r\n", i, i).as_bytes());
    }
    payload.extend_from_slice(b"\r\n");

    let packets = build_tcp_stream([10, 0, 0, 1], [10, 0, 0, 2], 1234, 80, &payload);
    let refs: Vec<(&[u8], u32, u32)> = packets
        .iter()
        .map(|(d, s, u)| (d.as_slice(), *s, *u))
        .collect();
    write_pcap(&path, &refs);

    let output = netgrep()
        .args(["-I", path.to_str().unwrap(), "--http"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let _ = std::fs::remove_file(&path);
}

#[test]
fn http_smuggling_detection() {
    // Both Content-Length and Transfer-Encoding — potential smuggling
    let path = temp_pcap("http_smuggling");
    let payload =
        b"POST /api HTTP/1.1\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n";
    let packets = build_tcp_stream([10, 0, 0, 1], [10, 0, 0, 2], 1234, 80, payload);
    let refs: Vec<(&[u8], u32, u32)> = packets
        .iter()
        .map(|(d, s, u)| (d.as_slice(), *s, *u))
        .collect();
    write_pcap(&path, &refs);

    let output = netgrep()
        .args(["-I", path.to_str().unwrap(), "--http"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    // Should flag the smuggling risk
    assert!(
        stdout.contains("WARNING") || stdout.contains("smuggling"),
        "Should warn about smuggling: {}",
        stdout
    );
    let _ = std::fs::remove_file(&path);
}

#[test]
fn http_response_no_reason_phrase() {
    // HTTP/1.1 204 (no reason) followed by another message
    let path = temp_pcap("http_no_reason");
    let payload = b"HTTP/1.1 204\r\n\r\nGET / HTTP/1.1\r\nHost: x\r\n\r\n";
    let packets = build_tcp_stream([10, 0, 0, 2], [10, 0, 0, 1], 80, 1234, payload);
    let refs: Vec<(&[u8], u32, u32)> = packets
        .iter()
        .map(|(d, s, u)| (d.as_slice(), *s, *u))
        .collect();
    write_pcap(&path, &refs);

    let output = netgrep()
        .args(["-I", path.to_str().unwrap(), "--http"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let _ = std::fs::remove_file(&path);
}

#[test]
fn http_chunked_with_huge_chunk_size_line() {
    // Chunk size line > 100 chars — should be rejected safely
    let path = temp_pcap("http_huge_chunk");
    let mut payload = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
    // 150-char chunk size line
    payload.extend_from_slice(&vec![b'a'; 150]);
    payload.extend_from_slice(b"\r\n");

    let packets = build_tcp_stream([10, 0, 0, 2], [10, 0, 0, 1], 80, 1234, &payload);
    let refs: Vec<(&[u8], u32, u32)> = packets
        .iter()
        .map(|(d, s, u)| (d.as_slice(), *s, *u))
        .collect();
    write_pcap(&path, &refs);

    let output = netgrep()
        .args(["-I", path.to_str().unwrap(), "--http"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let _ = std::fs::remove_file(&path);
}

// =============================================================================
// DNS parser stress tests
// =============================================================================

#[test]
fn dns_garbage_payload() {
    // Random bytes on port 53 — should not crash the DNS parser
    let path = temp_pcap("dns_garbage");
    let garbage: Vec<u8> = (0..100).map(|i| (i * 37 + 13) as u8).collect();
    let udp = build_eth_udp_packet([10, 0, 0, 1], [8, 8, 8, 8], 5000, 53, &garbage);
    write_pcap(&path, &[(&udp, 1000, 0)]);

    let output = netgrep()
        .args(["-I", path.to_str().unwrap(), "--dns", "--no-reassemble"])
        .output()
        .unwrap();
    // Should succeed (just not parse the DNS) or fail gracefully
    assert!(output.status.success());
    let _ = std::fs::remove_file(&path);
}

#[test]
fn dns_empty_payload_on_port_53() {
    // Empty UDP payload on port 53
    let path = temp_pcap("dns_empty");
    let udp = build_eth_udp_packet([10, 0, 0, 1], [8, 8, 8, 8], 5000, 53, &[]);
    write_pcap(&path, &[(&udp, 1000, 0)]);

    let output = netgrep()
        .args(["-I", path.to_str().unwrap(), "--dns", "--no-reassemble"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let _ = std::fs::remove_file(&path);
}

#[test]
fn dns_single_byte_payload() {
    let path = temp_pcap("dns_one_byte");
    let udp = build_eth_udp_packet([10, 0, 0, 1], [8, 8, 8, 8], 5000, 53, &[0xFF]);
    write_pcap(&path, &[(&udp, 1000, 0)]);

    let output = netgrep()
        .args(["-I", path.to_str().unwrap(), "--dns", "--no-reassemble"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let _ = std::fs::remove_file(&path);
}

// =============================================================================
// Stream reassembly stress tests
// =============================================================================

#[test]
fn many_streams_no_crash() {
    // 100 distinct TCP streams in one pcap
    let path = temp_pcap("many_streams");
    let mut all_packets: Vec<(Vec<u8>, u32, u32)> = Vec::new();
    for i in 0..100u16 {
        let src = [10, 0, (i >> 8) as u8, (i & 0xFF) as u8];
        let payload = format!("stream_{}", i);
        let stream = build_tcp_stream(src, [10, 0, 0, 2], 1000 + i, 80, payload.as_bytes());
        for (pkt, ts_s, ts_u) in stream {
            all_packets.push((pkt, ts_s + i as u32, ts_u));
        }
    }
    let refs: Vec<(&[u8], u32, u32)> = all_packets
        .iter()
        .map(|(d, s, u)| (d.as_slice(), *s, *u))
        .collect();
    write_pcap(&path, &refs);

    let output = netgrep()
        .args(["-I", path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("100 matches"),
        "Expected 100 matches: {}",
        stderr
    );
    let _ = std::fs::remove_file(&path);
}

#[test]
fn large_stream_payload() {
    // Large payload split across multiple TCP segments (IP max payload ~65KB)
    let path = temp_pcap("large_payload");
    let chunk = vec![b'A'; 30_000]; // fits in one IP packet
    let syn = build_eth_tcp_packet([10, 0, 0, 1], [10, 0, 0, 2], 1234, 80, 100, 0x02, &[]);
    let syn_ack = build_eth_tcp_packet([10, 0, 0, 2], [10, 0, 0, 1], 80, 1234, 200, 0x12, &[]);
    let data1 = build_eth_tcp_packet(
        [10, 0, 0, 1],
        [10, 0, 0, 2],
        1234,
        80,
        101,
        0x10, // ACK only
        &chunk,
    );
    let data2 = build_eth_tcp_packet(
        [10, 0, 0, 1],
        [10, 0, 0, 2],
        1234,
        80,
        101 + chunk.len() as u32,
        0x18, // PSH+ACK
        &chunk,
    );
    let packets: Vec<(Vec<u8>, u32, u32)> = vec![
        (syn, 1000, 0),
        (syn_ack, 1000, 1000),
        (data1, 1000, 2000),
        (data2, 1000, 3000),
    ];
    let refs: Vec<(&[u8], u32, u32)> = packets
        .iter()
        .map(|(d, s, u)| (d.as_slice(), *s, *u))
        .collect();
    write_pcap(&path, &refs);

    let output = netgrep()
        .args(["-I", path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    // Should have reassembled the stream (60KB of 'A's)
    assert!(
        stdout.len() >= 50_000,
        "Large payload should be reassembled"
    );
    let _ = std::fs::remove_file(&path);
}

#[test]
fn only_syn_packets_no_data() {
    // pcap with only SYN packets (no data, no PSH) — should produce no output
    let path = temp_pcap("syn_only");
    let syn1 = build_eth_tcp_packet([10, 0, 0, 1], [10, 0, 0, 2], 1234, 80, 100, 0x02, &[]);
    let syn2 = build_eth_tcp_packet([10, 0, 0, 3], [10, 0, 0, 4], 5678, 443, 200, 0x02, &[]);
    write_pcap(&path, &[(&syn1, 1000, 0), (&syn2, 1001, 0)]);

    let output = netgrep()
        .args(["-I", path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.is_empty(), "SYN-only should produce no output");
    let _ = std::fs::remove_file(&path);
}

#[test]
fn rst_without_prior_data() {
    // RST packet on a stream with no data — should not crash
    let path = temp_pcap("rst_no_data");
    let syn = build_eth_tcp_packet([10, 0, 0, 1], [10, 0, 0, 2], 1234, 80, 100, 0x02, &[]);
    let rst = build_eth_tcp_packet([10, 0, 0, 1], [10, 0, 0, 2], 1234, 80, 101, 0x04, &[]);
    write_pcap(&path, &[(&syn, 1000, 0), (&rst, 1000, 1000)]);

    let output = netgrep()
        .args(["-I", path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(output.status.success());
    let _ = std::fs::remove_file(&path);
}

#[test]
fn fin_with_payload() {
    // FIN packet carrying payload data
    let path = temp_pcap("fin_payload");
    let syn = build_eth_tcp_packet([10, 0, 0, 1], [10, 0, 0, 2], 1234, 80, 100, 0x02, &[]);
    let syn_ack = build_eth_tcp_packet([10, 0, 0, 2], [10, 0, 0, 1], 80, 1234, 200, 0x12, &[]);
    // FIN+ACK with payload
    let fin_data = build_eth_tcp_packet(
        [10, 0, 0, 1],
        [10, 0, 0, 2],
        1234,
        80,
        101,
        0x11, // FIN+ACK
        b"final data",
    );
    write_pcap(
        &path,
        &[
            (&syn, 1000, 0),
            (&syn_ack, 1000, 1000),
            (&fin_data, 1000, 2000),
        ],
    );

    let output = netgrep()
        .args(["-I", path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("final data"),
        "FIN with payload should be captured: {}",
        stdout
    );
    let _ = std::fs::remove_file(&path);
}

#[test]
fn udp_packet_no_reassembly_needed() {
    // Pure UDP traffic — reassembly should be skipped
    let path = temp_pcap("udp_only");
    let udp1 = build_eth_udp_packet([10, 0, 0, 1], [10, 0, 0, 2], 5000, 8080, b"udp payload 1");
    let udp2 = build_eth_udp_packet([10, 0, 0, 1], [10, 0, 0, 2], 5001, 8080, b"udp payload 2");
    write_pcap(&path, &[(&udp1, 1000, 0), (&udp2, 1001, 0)]);

    let output = netgrep()
        .args(["-I", path.to_str().unwrap(), "--no-reassemble", "udp"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("udp payload"),
        "UDP data should be matched: {}",
        stdout
    );
    let _ = std::fs::remove_file(&path);
}

// =============================================================================
// Output file writing stress tests
// =============================================================================

#[test]
fn output_file_written_correctly() {
    let input_path = temp_pcap("output_input");
    let output_path =
        std::env::temp_dir().join(format!("netgrep_stress_output_{}.pcap", std::process::id()));
    // Make sure output doesn't exist
    let _ = std::fs::remove_file(&output_path);

    let packets = build_tcp_stream([10, 0, 0, 1], [10, 0, 0, 2], 1234, 80, b"write me");
    let refs: Vec<(&[u8], u32, u32)> = packets
        .iter()
        .map(|(d, s, u)| (d.as_slice(), *s, *u))
        .collect();
    write_pcap(&input_path, &refs);

    let output = netgrep()
        .args([
            "-I",
            input_path.to_str().unwrap(),
            "-O",
            output_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(output.status.success());
    // Output file should exist and be non-empty
    assert!(output_path.exists(), "Output file should be created");
    let metadata = std::fs::metadata(&output_path).unwrap();
    assert!(metadata.len() > 24, "Output pcap should have data");

    let _ = std::fs::remove_file(&input_path);
    let _ = std::fs::remove_file(&output_path);
}

// =============================================================================
// Pattern matching edge cases
// =============================================================================

#[test]
fn regex_special_chars_in_pattern() {
    // Pattern with regex special characters
    let path = temp_pcap("regex_special");
    let payload = b"price: $99.99 (USD)";
    let packets = build_tcp_stream([10, 0, 0, 1], [10, 0, 0, 2], 1234, 80, payload);
    let refs: Vec<(&[u8], u32, u32)> = packets
        .iter()
        .map(|(d, s, u)| (d.as_slice(), *s, *u))
        .collect();
    write_pcap(&path, &refs);

    let output = netgrep()
        .args(["-I", path.to_str().unwrap(), r"\$\d+\.\d+"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("$99.99"),
        "Should match dollar amount: {}",
        stdout
    );
    let _ = std::fs::remove_file(&path);
}

#[test]
fn invert_match_with_no_matching_streams() {
    // Invert match where nothing matches the pattern — all streams should be shown
    let path = temp_pcap("invert_all");
    let packets = build_tcp_stream([10, 0, 0, 1], [10, 0, 0, 2], 1234, 80, b"actual data");
    let refs: Vec<(&[u8], u32, u32)> = packets
        .iter()
        .map(|(d, s, u)| (d.as_slice(), *s, *u))
        .collect();
    write_pcap(&path, &refs);

    let output = netgrep()
        .args(["-I", path.to_str().unwrap(), "-v", "ZZZZNOTFOUND"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("actual data"),
        "Inverted match should show non-matching: {}",
        stdout
    );
    let _ = std::fs::remove_file(&path);
}

#[test]
fn case_insensitive_with_unicode_like_bytes() {
    let path = temp_pcap("case_unicode");
    let payload = b"Content-Type: text/HTML; charset=UTF-8";
    let packets = build_tcp_stream([10, 0, 0, 1], [10, 0, 0, 2], 1234, 80, payload);
    let refs: Vec<(&[u8], u32, u32)> = packets
        .iter()
        .map(|(d, s, u)| (d.as_slice(), *s, *u))
        .collect();
    write_pcap(&path, &refs);

    let output = netgrep()
        .args(["-I", path.to_str().unwrap(), "-i", "text/html"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("text/HTML"), "Case insensitive: {}", stdout);
    let _ = std::fs::remove_file(&path);
}

// =============================================================================
// Concurrent flag combinations
// =============================================================================

#[test]
fn dns_json_mode() {
    use simple_dns::{CLASS, Name, Packet, QCLASS, QTYPE, Question, TYPE};

    let path = temp_pcap("dns_json");
    let mut pkt_dns = Packet::new_query(0x1234);
    pkt_dns.questions.push(Question::new(
        Name::new("test.example.com").unwrap(),
        QTYPE::TYPE(TYPE::A),
        QCLASS::CLASS(CLASS::IN),
        false,
    ));
    let wire = pkt_dns.build_bytes_vec().unwrap();
    let udp = build_eth_udp_packet([10, 0, 0, 1], [8, 8, 8, 8], 5000, 53, &wire);
    write_pcap(&path, &[(&udp, 1000, 0)]);

    let output = netgrep()
        .args([
            "-I",
            path.to_str().unwrap(),
            "--dns",
            "--json",
            "--no-reassemble",
        ])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in stdout.lines() {
        if !line.trim().is_empty() {
            let v: serde_json::Value = serde_json::from_str(line)
                .unwrap_or_else(|e| panic!("DNS JSON invalid: {} line: {}", e, line));
            assert!(v["type"].is_string());
        }
    }
    let _ = std::fs::remove_file(&path);
}

#[test]
fn http_json_mode() {
    let path = temp_pcap("http_json");
    let payload = b"GET /api HTTP/1.1\r\nHost: example.com\r\n\r\n";
    let packets = build_tcp_stream([10, 0, 0, 1], [10, 0, 0, 2], 1234, 80, payload);
    let refs: Vec<(&[u8], u32, u32)> = packets
        .iter()
        .map(|(d, s, u)| (d.as_slice(), *s, *u))
        .collect();
    write_pcap(&path, &refs);

    let output = netgrep()
        .args(["-I", path.to_str().unwrap(), "--http", "--json"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in stdout.lines() {
        if !line.trim().is_empty() {
            let v: serde_json::Value = serde_json::from_str(line)
                .unwrap_or_else(|e| panic!("HTTP JSON invalid: {} line: {}", e, line));
            assert!(v["type"].is_string());
        }
    }
    let _ = std::fs::remove_file(&path);
}

#[test]
fn http_hex_mode() {
    let path = temp_pcap("http_hex");
    let payload = b"GET /test HTTP/1.1\r\nHost: x\r\n\r\n";
    let packets = build_tcp_stream([10, 0, 0, 1], [10, 0, 0, 2], 1234, 80, payload);
    let refs: Vec<(&[u8], u32, u32)> = packets
        .iter()
        .map(|(d, s, u)| (d.as_slice(), *s, *u))
        .collect();
    write_pcap(&path, &refs);

    let output = netgrep()
        .args(["-I", path.to_str().unwrap(), "--http", "-x"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let _ = std::fs::remove_file(&path);
}
