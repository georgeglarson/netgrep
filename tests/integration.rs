use std::path::Path;
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

// =============================================================================
// Pcap helpers
// =============================================================================

/// Write a minimal valid pcap file (header only, no packets).
fn write_empty_pcap(path: &Path) {
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

/// Build an Ethernet + IPv4 + TCP packet using etherparse.
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
    // Set TCP flags manually: eth(14) + ipv4(20) + tcp_flags_offset(13) = 47
    buf[14 + 20 + 13] = flags_byte;
    buf
}

/// Build an Ethernet + IPv4 + UDP packet using etherparse.
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

/// Write a pcap file with the given packets.
/// Each entry is (packet_bytes, ts_sec, ts_usec).
fn write_pcap(path: &Path, packets: &[(&[u8], u32, u32)]) {
    let mut data = Vec::new();
    // Global header (little-endian)
    data.extend_from_slice(&0xa1b2c3d4u32.to_le_bytes()); // magic
    data.extend_from_slice(&2u16.to_le_bytes()); // major
    data.extend_from_slice(&4u16.to_le_bytes()); // minor
    data.extend_from_slice(&0i32.to_le_bytes()); // thiszone
    data.extend_from_slice(&0u32.to_le_bytes()); // sigfigs
    data.extend_from_slice(&65535u32.to_le_bytes()); // snaplen
    data.extend_from_slice(&1u32.to_le_bytes()); // Ethernet

    for &(pkt, ts_sec, ts_usec) in packets {
        let len = pkt.len() as u32;
        data.extend_from_slice(&ts_sec.to_le_bytes());
        data.extend_from_slice(&ts_usec.to_le_bytes());
        data.extend_from_slice(&len.to_le_bytes()); // incl_len
        data.extend_from_slice(&len.to_le_bytes()); // orig_len
        data.extend_from_slice(pkt);
    }
    std::fs::write(path, &data).unwrap();
}

/// Build a TCP stream: SYN + SYN-ACK + PSH|ACK with payload.
/// Returns packets suitable for write_pcap.
fn build_tcp_stream(
    src_ip: [u8; 4],
    dst_ip: [u8; 4],
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Vec<(Vec<u8>, u32, u32)> {
    let syn = build_eth_tcp_packet(src_ip, dst_ip, src_port, dst_port, 100, 0x02, &[]); // SYN
    let syn_ack = build_eth_tcp_packet(dst_ip, src_ip, dst_port, src_port, 200, 0x12, &[]); // SYN+ACK
    let psh_ack = build_eth_tcp_packet(src_ip, dst_ip, src_port, dst_port, 101, 0x18, payload); // PSH+ACK
    vec![(syn, 1000, 0), (syn_ack, 1000, 1000), (psh_ack, 1000, 2000)]
}

/// Helper to create a temp pcap path with a unique name.
fn temp_pcap(name: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!("netgrep_e2e_{}_{}.pcap", name, std::process::id()))
}

// =============================================================================
// E2E pcap-based tests
// =============================================================================

#[test]
fn pcap_match_tcp_payload() {
    let path = temp_pcap("match_tcp");
    let packets = build_tcp_stream([10, 0, 0, 1], [10, 0, 0, 2], 1234, 80, b"hello world");
    let refs: Vec<(&[u8], u32, u32)> = packets
        .iter()
        .map(|(d, s, u)| (d.as_slice(), *s, *u))
        .collect();
    write_pcap(&path, &refs);

    let output = netgrep()
        .args(["-I", path.to_str().unwrap(), "hello"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("hello"), "stdout: {}", stdout);

    let _ = std::fs::remove_file(&path);
}

#[test]
fn pcap_no_match_exits_clean() {
    let path = temp_pcap("no_match");
    let packets = build_tcp_stream([10, 0, 0, 1], [10, 0, 0, 2], 1234, 80, b"hello world");
    let refs: Vec<(&[u8], u32, u32)> = packets
        .iter()
        .map(|(d, s, u)| (d.as_slice(), *s, *u))
        .collect();
    write_pcap(&path, &refs);

    let output = netgrep()
        .args(["-I", path.to_str().unwrap(), "zzzznotfound"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.is_empty() || !stdout.contains("zzzznotfound"));

    let _ = std::fs::remove_file(&path);
}

#[test]
fn pcap_case_insensitive() {
    let path = temp_pcap("case_insensitive");
    let packets = build_tcp_stream([10, 0, 0, 1], [10, 0, 0, 2], 1234, 80, b"Hello World");
    let refs: Vec<(&[u8], u32, u32)> = packets
        .iter()
        .map(|(d, s, u)| (d.as_slice(), *s, *u))
        .collect();
    write_pcap(&path, &refs);

    let output = netgrep()
        .args(["-I", path.to_str().unwrap(), "-i", "HELLO"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Hello"), "stdout: {}", stdout);

    let _ = std::fs::remove_file(&path);
}

#[test]
fn pcap_inverted_match() {
    let path = temp_pcap("inverted");
    let packets = build_tcp_stream([10, 0, 0, 1], [10, 0, 0, 2], 1234, 80, b"hello");
    let refs: Vec<(&[u8], u32, u32)> = packets
        .iter()
        .map(|(d, s, u)| (d.as_slice(), *s, *u))
        .collect();
    write_pcap(&path, &refs);

    let output = netgrep()
        .args(["-I", path.to_str().unwrap(), "-v", "hello"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    // With only one stream matching "hello", invert should produce no output
    assert!(
        !stdout.contains("hello"),
        "stdout should not contain 'hello': {}",
        stdout
    );

    let _ = std::fs::remove_file(&path);
}

#[test]
fn pcap_json_output() {
    let path = temp_pcap("json");
    let packets = build_tcp_stream([10, 0, 0, 1], [10, 0, 0, 2], 1234, 80, b"test data");
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
    // Each non-empty line should be valid JSON
    for line in stdout.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let v: serde_json::Value = serde_json::from_str(line).unwrap_or_else(|e| {
            panic!("Invalid JSON: {} in line: {}", e, line);
        });
        assert!(v["type"].is_string());
    }

    let _ = std::fs::remove_file(&path);
}

#[test]
fn pcap_hex_output() {
    let path = temp_pcap("hex");
    let packets = build_tcp_stream([10, 0, 0, 1], [10, 0, 0, 2], 1234, 80, b"hex test data");
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
    assert!(stdout.contains("00000000"), "stdout: {}", stdout);

    let _ = std::fs::remove_file(&path);
}

#[test]
fn pcap_count_limit() {
    let path = temp_pcap("count_limit");
    // Build two separate streams so we get 2 matches
    let mut packets = build_tcp_stream([10, 0, 0, 1], [10, 0, 0, 2], 1234, 80, b"match1");
    let stream2 = build_tcp_stream([10, 0, 0, 3], [10, 0, 0, 4], 5678, 80, b"match2");
    // Offset stream2 timestamps
    for (pkt, ts_s, ts_u) in stream2 {
        packets.push((pkt, ts_s + 1, ts_u));
    }
    let refs: Vec<(&[u8], u32, u32)> = packets
        .iter()
        .map(|(d, s, u)| (d.as_slice(), *s, *u))
        .collect();
    write_pcap(&path, &refs);

    let output = netgrep()
        .args(["-I", path.to_str().unwrap(), "-n", "1"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    // Should show "1 matches" (limited to 1)
    assert!(stderr.contains("1 matches"), "stderr: {}", stderr);

    let _ = std::fs::remove_file(&path);
}

#[test]
fn pcap_quiet_mode() {
    let path = temp_pcap("quiet");
    let packets = build_tcp_stream([10, 0, 0, 1], [10, 0, 0, 2], 1234, 80, b"quiet data");
    let refs: Vec<(&[u8], u32, u32)> = packets
        .iter()
        .map(|(d, s, u)| (d.as_slice(), *s, *u))
        .collect();
    write_pcap(&path, &refs);

    let output = netgrep()
        .args(["-I", path.to_str().unwrap(), "-q", "quiet"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("quiet data"), "stdout: {}", stdout);
    // In quiet mode, the header goes to stderr but should NOT contain the "STREAM" label
    // (quiet suppresses headers)
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("STREAM"),
        "stderr should not have STREAM header in quiet mode: {}",
        stderr
    );

    let _ = std::fs::remove_file(&path);
}

#[test]
fn pcap_dns_query() {
    use simple_dns::{CLASS, Name, Packet, QCLASS, QTYPE, Question, TYPE};

    let path = temp_pcap("dns_query");
    let mut pkt_dns = Packet::new_query(0x1234);
    pkt_dns.questions.push(Question::new(
        Name::new("example.com").unwrap(),
        QTYPE::TYPE(TYPE::A),
        QCLASS::CLASS(CLASS::IN),
        false,
    ));
    let wire = pkt_dns.build_bytes_vec().unwrap();

    let udp = build_eth_udp_packet([10, 0, 0, 1], [8, 8, 8, 8], 5000, 53, &wire);
    write_pcap(&path, &[(&udp, 1000, 0)]);

    let output = netgrep()
        .args(["-I", path.to_str().unwrap(), "--dns", "--no-reassemble"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("example.com"),
        "stderr should contain domain: {}",
        stderr
    );

    let _ = std::fs::remove_file(&path);
}

#[test]
fn pcap_http_request() {
    let path = temp_pcap("http_request");
    let http_payload = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n";
    let packets = build_tcp_stream([10, 0, 0, 1], [10, 0, 0, 2], 1234, 80, http_payload);
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
    assert!(stdout.contains("GET /index.html"), "stdout: {}", stdout);

    let _ = std::fs::remove_file(&path);
}

#[test]
fn pcap_no_reassemble() {
    let path = temp_pcap("no_reassemble");
    let packets = build_tcp_stream([10, 0, 0, 1], [10, 0, 0, 2], 1234, 80, b"per-packet");
    let refs: Vec<(&[u8], u32, u32)> = packets
        .iter()
        .map(|(d, s, u)| (d.as_slice(), *s, *u))
        .collect();
    write_pcap(&path, &refs);

    let output = netgrep()
        .args([
            "-I",
            path.to_str().unwrap(),
            "--no-reassemble",
            "per-packet",
        ])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    // In no-reassemble mode, output shows individual packet info (Tcp), not STREAM
    assert!(
        !stderr.contains("STREAM"),
        "should not show STREAM in no-reassemble mode: {}",
        stderr
    );

    let _ = std::fs::remove_file(&path);
}

#[test]
fn pcap_bpf_filter() {
    let path = temp_pcap("bpf_filter");
    // Build one stream on port 80, another on port 9999
    let mut packets = build_tcp_stream([10, 0, 0, 1], [10, 0, 0, 2], 1234, 80, b"port80data");
    let stream2 = build_tcp_stream([10, 0, 0, 3], [10, 0, 0, 4], 5678, 9999, b"port9999data");
    for (pkt, ts_s, ts_u) in stream2 {
        packets.push((pkt, ts_s + 1, ts_u));
    }
    let refs: Vec<(&[u8], u32, u32)> = packets
        .iter()
        .map(|(d, s, u)| (d.as_slice(), *s, *u))
        .collect();
    write_pcap(&path, &refs);

    let output = netgrep()
        .args(["-I", path.to_str().unwrap(), "-F", "tcp port 80"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("port80data"), "stdout: {}", stdout);
    assert!(
        !stdout.contains("port9999data"),
        "should not contain port 9999 data: {}",
        stdout
    );

    let _ = std::fs::remove_file(&path);
}

// =============================================================================
// Golden / snapshot output tests (Phase 6)
// =============================================================================

#[test]
fn golden_text_tcp_stream() {
    let path = temp_pcap("golden_text");
    let packets = build_tcp_stream([10, 0, 0, 1], [10, 0, 0, 2], 1234, 80, b"hello world");
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
    assert_eq!(stdout.trim(), "hello world");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("STREAM"));
    assert!(stderr.contains("11 bytes"));
    assert!(stderr.contains("1 matches"));

    let _ = std::fs::remove_file(&path);
}

#[test]
fn golden_json_tcp_stream() {
    let path = temp_pcap("golden_json");
    let packets = build_tcp_stream([10, 0, 0, 1], [10, 0, 0, 2], 1234, 80, b"hello world");
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
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap();
    assert_eq!(v["type"], "stream");
    assert_eq!(v["payload"], "hello world");
    assert_eq!(v["payload_len"], 11);

    let _ = std::fs::remove_file(&path);
}

#[test]
fn golden_hex_dump() {
    let path = temp_pcap("golden_hex");
    let packets = build_tcp_stream([10, 0, 0, 1], [10, 0, 0, 2], 1234, 80, b"ABCDEFGH");
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
    assert!(stdout.contains("00000000  "), "stdout: {}", stdout);
    assert!(
        stdout.contains("41 42 43 44 45 46 47 48"),
        "stdout: {}",
        stdout
    );
    assert!(stdout.contains("|ABCDEFGH|"), "stdout: {}", stdout);

    let _ = std::fs::remove_file(&path);
}

#[test]
fn golden_dns_response() {
    use simple_dns::rdata::RData;
    use simple_dns::{CLASS, Name, Packet, QCLASS, QTYPE, Question, ResourceRecord, TYPE};

    let path = temp_pcap("golden_dns");
    let mut pkt_dns = Packet::new_reply(0x1234);
    pkt_dns.questions.push(Question::new(
        Name::new("example.com").unwrap(),
        QTYPE::TYPE(TYPE::A),
        QCLASS::CLASS(CLASS::IN),
        false,
    ));
    pkt_dns.answers.push(ResourceRecord::new(
        Name::new("example.com").unwrap(),
        CLASS::IN,
        300,
        RData::A(simple_dns::rdata::A {
            address: std::net::Ipv4Addr::new(93, 184, 216, 34).into(),
        }),
    ));
    let wire = pkt_dns.build_bytes_vec().unwrap();

    let udp = build_eth_udp_packet([8, 8, 8, 8], [10, 0, 0, 1], 53, 5000, &wire);
    write_pcap(&path, &[(&udp, 1000, 0)]);

    let output = netgrep()
        .args(["-I", path.to_str().unwrap(), "--dns", "--no-reassemble"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("DNS R"), "stderr: {}", stderr);
    assert!(stderr.contains("example.com"), "stderr: {}", stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("93.184.216.34"), "stdout: {}", stdout);

    let _ = std::fs::remove_file(&path);
}

#[test]
fn golden_http_request() {
    let path = temp_pcap("golden_http");
    let http_payload = b"GET /api/v1 HTTP/1.1\r\nHost: api.example.com\r\n\r\n";
    let packets = build_tcp_stream([10, 0, 0, 1], [10, 0, 0, 2], 1234, 80, http_payload);
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
    assert!(
        stdout.contains("GET /api/v1 HTTP/1.1"),
        "stdout: {}",
        stdout
    );
    assert!(
        stdout.contains("Host: api.example.com"),
        "stdout: {}",
        stdout
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("HTTP"), "stderr: {}", stderr);

    let _ = std::fs::remove_file(&path);
}
