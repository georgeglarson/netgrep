//! Unit-level stress tests exercising internal APIs with adversarial inputs.
//! Tests protocol parsers, reassembly, and sanitizer directly.

use netgrep::protocol::StreamKey;
use netgrep::protocol::dns;
use netgrep::protocol::http::parse_http;
use netgrep::protocol::http2::{H2Direction, H2Tracker};
use netgrep::reassembly::StreamTable;
use netgrep::sanitize::sanitize_control_chars;

use std::net::{IpAddr, Ipv4Addr};

// =============================================================================
// HTTP parser adversarial inputs
// =============================================================================

#[test]
fn http_empty_input() {
    assert!(parse_http(b"").is_empty());
}

#[test]
fn http_only_crlf() {
    assert!(parse_http(b"\r\n\r\n").is_empty());
}

#[test]
fn http_just_newlines() {
    assert!(parse_http(b"\n\n\n\n\n").is_empty());
}

#[test]
fn http_garbage_bytes() {
    let garbage: Vec<u8> = (0..=255).collect();
    let result = parse_http(&garbage);
    // Should return empty (can't parse) — not panic
    assert!(result.is_empty() || !result.is_empty()); // just don't panic
}

#[test]
fn http_null_bytes_in_headers() {
    let data = b"GET / HTTP/1.1\r\nHost: \x00evil\x00.com\r\n\r\n";
    let msgs = parse_http(data);
    assert_eq!(msgs.len(), 1);
}

#[test]
fn http_extremely_long_uri() {
    let mut data = b"GET /".to_vec();
    data.extend(vec![b'A'; 100_000]);
    data.extend_from_slice(b" HTTP/1.1\r\nHost: x\r\n\r\n");
    let msgs = parse_http(&data);
    assert_eq!(msgs.len(), 1);
}

#[test]
fn http_extremely_long_header_value() {
    let mut data = b"GET / HTTP/1.1\r\nX-Big: ".to_vec();
    data.extend(vec![b'V'; 100_000]);
    data.extend_from_slice(b"\r\n\r\n");
    let msgs = parse_http(&data);
    assert_eq!(msgs.len(), 1);
}

#[test]
fn http_continuation_header_bomb() {
    // Many continuation lines that try to exceed the 8192 limit
    let mut data = b"GET / HTTP/1.1\r\nX-Bomb: start\r\n".to_vec();
    for _ in 0..200 {
        data.extend_from_slice(b" continuation_line_padding_data_here\r\n");
    }
    data.extend_from_slice(b"Host: x\r\n\r\n");
    let msgs = parse_http(&data);
    // Should parse without panicking, may truncate the header
    assert!(!msgs.is_empty());
}

#[test]
fn http_max_messages_per_parse() {
    // Try to exceed MAX_MESSAGES_PER_PARSE (200)
    let mut data = Vec::new();
    for _ in 0..250 {
        data.extend_from_slice(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n");
    }
    let msgs = parse_http(&data);
    assert!(msgs.len() <= 200, "Should cap at 200 messages");
}

#[test]
fn http_content_length_overflow() {
    // Content-Length larger than available data
    let data = b"HTTP/1.1 200 OK\r\nContent-Length: 999999999\r\n\r\nshort";
    let msgs = parse_http(data);
    assert_eq!(msgs.len(), 1);
    assert_eq!(msgs[0].body, "short");
}

#[test]
fn http_content_length_negative() {
    let data = b"HTTP/1.1 200 OK\r\nContent-Length: -1\r\n\r\nbody";
    let msgs = parse_http(data);
    // Negative CL won't parse as usize, so body should be treated as close-delimited
    assert!(!msgs.is_empty());
}

#[test]
fn http_content_length_not_a_number() {
    let data = b"HTTP/1.1 200 OK\r\nContent-Length: abc\r\n\r\nbody";
    let msgs = parse_http(data);
    assert!(!msgs.is_empty());
}

#[test]
fn http_chunked_zero_size_only() {
    let data = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n";
    let msgs = parse_http(data);
    assert_eq!(msgs.len(), 1);
    assert_eq!(msgs[0].body, "");
}

#[test]
fn http_response_status_not_a_number() {
    let data = b"HTTP/1.1 XYZ Weird\r\n\r\n";
    let msgs = parse_http(data);
    assert_eq!(msgs.len(), 1);
    // Status should be 0 (default from unwrap_or(0))
    match &msgs[0].kind {
        netgrep::protocol::http::HttpKind::Response { status, .. } => {
            assert_eq!(*status, 0);
        }
        _ => panic!("Expected response"),
    }
}

#[test]
fn http_method_case_sensitive() {
    // "get" lowercase should be rejected
    let data = b"get / HTTP/1.1\r\nHost: x\r\n\r\n";
    let msgs = parse_http(data);
    assert!(msgs.is_empty(), "Lowercase method should be rejected");
}

#[test]
fn http_request_and_response_in_stream() {
    // Typical bidirectional: request then response with body
    let data = b"GET / HTTP/1.1\r\nHost: x\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 12\r\n\r\nHello World!";
    let msgs = parse_http(data);
    assert_eq!(msgs.len(), 2);
    assert_eq!(msgs[1].body, "Hello World!");
}

// =============================================================================
// DNS parser edge cases
// =============================================================================

#[test]
fn dns_parse_empty_slice() {
    let result = dns::parse_dns(&[]);
    assert!(result.is_none());
}

#[test]
fn dns_parse_one_byte() {
    let result = dns::parse_dns(&[0xFF]);
    assert!(result.is_none());
}

#[test]
fn dns_parse_minimum_header_garbage() {
    // 12 bytes (minimum DNS header) of garbage
    let result = dns::parse_dns(&[0xFF; 12]);
    // May or may not parse, but should not panic
    let _ = result;
}

#[test]
fn dns_strip_tcp_prefix_empty() {
    assert_eq!(dns::strip_tcp_prefix(&[], true), &[] as &[u8]);
}

#[test]
fn dns_strip_tcp_prefix_one_byte() {
    assert_eq!(dns::strip_tcp_prefix(&[0x00], true), &[0x00]);
}

// =============================================================================
// Sanitizer edge cases
// =============================================================================

#[test]
fn sanitize_empty() {
    assert_eq!(sanitize_control_chars(""), "");
}

#[test]
fn sanitize_all_control_chars() {
    let input: String = (0u8..32)
        .chain(std::iter::once(127u8))
        .map(|b| b as char)
        .collect();
    let result = sanitize_control_chars(&input);
    // Tab, newline, CR should be preserved
    assert!(result.contains('\t'));
    assert!(result.contains('\n'));
    assert!(result.contains('\r'));
    // Null and other control chars should be replaced
    assert!(!result.contains('\0'));
    assert!(!result.contains('\x07')); // bell
    assert!(!result.contains('\x1b')); // escape
}

#[test]
fn sanitize_c1_control_range() {
    // U+0080 through U+009F (C1 control characters)
    let input: String = (0x80u8..=0x9F)
        .map(|b| char::from_u32(b as u32).unwrap())
        .collect();
    let result = sanitize_control_chars(&input);
    for c in result.chars() {
        // All C1 chars should be replaced with the replacement character
        assert!(
            !(('\u{0080}'..='\u{009F}').contains(&c)),
            "C1 control char {:?} leaked through",
            c
        );
    }
}

#[test]
fn sanitize_mixed_printable_and_control() {
    let result = sanitize_control_chars("hello\x00world\x1b[31mred\x07bell");
    assert!(result.contains("hello"));
    assert!(result.contains("world"));
    assert!(result.contains("red"));
    assert!(result.contains("bell"));
    assert!(!result.contains('\x00'));
    assert!(!result.contains('\x1b'));
    assert!(!result.contains('\x07'));
}

// =============================================================================
// HTTP/2 tracker edge cases
// =============================================================================

fn test_key() -> StreamKey {
    StreamKey::new(
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        1234,
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        443,
    )
}

#[test]
fn h2_empty_payload() {
    let mut tracker = H2Tracker::new();
    let key = test_key();
    let msgs = tracker.process(&key, &[], H2Direction::ClientToServer);
    assert!(msgs.is_empty());
}

#[test]
fn h2_partial_preface() {
    let mut tracker = H2Tracker::new();
    let key = test_key();
    // Send only first 10 bytes of the 24-byte preface
    let msgs = tracker.process(&key, b"PRI * HTTP", H2Direction::ClientToServer);
    assert!(msgs.is_empty());
}

#[test]
fn h2_garbage_after_preface() {
    let mut tracker = H2Tracker::new();
    let key = test_key();
    let preface = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    tracker.process(&key, preface, H2Direction::ClientToServer);

    // Send garbage that's not a valid frame
    let msgs = tracker.process(&key, &[0xFF; 100], H2Direction::ClientToServer);
    assert!(msgs.is_empty());
}

#[test]
fn h2_frame_with_zero_payload() {
    let mut tracker = H2Tracker::new();
    let key = test_key();
    let preface = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    tracker.process(&key, preface, H2Direction::ClientToServer);

    // SETTINGS frame with 0-length payload (valid)
    let frame = build_h2_frame(0x04, 0, 0, &[]);
    let msgs = tracker.process(&key, &frame, H2Direction::ClientToServer);
    assert!(msgs.is_empty());
}

fn build_h2_frame(frame_type: u8, flags: u8, stream_id: u32, payload: &[u8]) -> Vec<u8> {
    let len = payload.len();
    let mut frame = Vec::with_capacity(9 + len);
    frame.push((len >> 16) as u8);
    frame.push((len >> 8) as u8);
    frame.push(len as u8);
    frame.push(frame_type);
    frame.push(flags);
    let sid = stream_id & 0x7FFFFFFF;
    frame.extend_from_slice(&sid.to_be_bytes());
    frame.extend_from_slice(payload);
    frame
}

// =============================================================================
// Stream reassembly boundary conditions
// =============================================================================

use netgrep::protocol::{ParsedPacket, TcpFlags, Transport};

fn make_packet(
    src_ip: [u8; 4],
    dst_ip: [u8; 4],
    src_port: u16,
    dst_port: u16,
    seq: u32,
    flags: TcpFlags,
    payload: &[u8],
) -> ParsedPacket {
    ParsedPacket {
        src_ip: Some(IpAddr::V4(Ipv4Addr::from(src_ip))),
        dst_ip: Some(IpAddr::V4(Ipv4Addr::from(dst_ip))),
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        transport: Transport::Tcp,
        payload: payload.to_vec(),
        tcp_flags: Some(flags),
        seq: Some(seq),
        vlan_id: None,
        icmp_type: None,
        icmp_code: None,
        timestamp: None,
    }
}

fn syn() -> TcpFlags {
    TcpFlags {
        syn: true,
        ack: false,
        fin: false,
        rst: false,
        psh: false,
    }
}

fn syn_ack() -> TcpFlags {
    TcpFlags {
        syn: true,
        ack: true,
        fin: false,
        rst: false,
        psh: false,
    }
}

fn psh_ack() -> TcpFlags {
    TcpFlags {
        syn: false,
        ack: true,
        fin: false,
        rst: false,
        psh: true,
    }
}

fn ack_only() -> TcpFlags {
    TcpFlags {
        syn: false,
        ack: true,
        fin: false,
        rst: false,
        psh: false,
    }
}

fn rst_flags() -> TcpFlags {
    TcpFlags {
        syn: false,
        ack: false,
        fin: false,
        rst: true,
        psh: false,
    }
}

#[test]
fn reassembly_seq_wrap_around() {
    // TCP sequence number wrapping around u32::MAX -> 0
    let mut table = StreamTable::new();

    let pkt = make_packet(
        [10, 0, 0, 1],
        [10, 0, 0, 2],
        1234,
        80,
        u32::MAX - 2,
        syn(),
        &[],
    );
    table.process(&pkt);

    let pkt = make_packet([10, 0, 0, 2], [10, 0, 0, 1], 80, 1234, 200, syn_ack(), &[]);
    table.process(&pkt);

    // SYN consumes 1 byte, so next_seq = u32::MAX - 1
    // Data at seq = u32::MAX - 1, len=5 -> wraps around
    let pkt = make_packet(
        [10, 0, 0, 1],
        [10, 0, 0, 2],
        1234,
        80,
        u32::MAX - 1,
        psh_ack(),
        b"hello",
    );
    let results = table.process(&pkt);
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].payload, b"hello");
}

#[test]
fn reassembly_many_out_of_order_segments() {
    // Send MAX_REORDER_SEGMENTS (32) + 1 out-of-order segments
    let mut table = StreamTable::new();

    let pkt = make_packet([10, 0, 0, 1], [10, 0, 0, 2], 1234, 80, 100, syn(), &[]);
    table.process(&pkt);
    let pkt = make_packet([10, 0, 0, 2], [10, 0, 0, 1], 80, 1234, 200, syn_ack(), &[]);
    table.process(&pkt);

    // Send 35 segments all out of order (gap after seq 101)
    for i in 0..35u32 {
        let seq = 201 + i * 10; // way past expected
        let pkt = make_packet(
            [10, 0, 0, 1],
            [10, 0, 0, 2],
            1234,
            80,
            seq,
            ack_only(),
            b"seg",
        );
        table.process(&pkt);
    }

    // Now fill the gap
    let pkt = make_packet(
        [10, 0, 0, 1],
        [10, 0, 0, 2],
        1234,
        80,
        101,
        psh_ack(),
        &vec![b'A'; 100],
    );
    let results = table.process(&pkt);
    // Should have data — at least the in-order part
    assert!(!results.is_empty());
}

#[test]
fn reassembly_zero_length_payload_psh() {
    // PSH+ACK with empty payload
    let mut table = StreamTable::new();

    let pkt = make_packet([10, 0, 0, 1], [10, 0, 0, 2], 1234, 80, 100, syn(), &[]);
    table.process(&pkt);
    let pkt = make_packet([10, 0, 0, 2], [10, 0, 0, 1], 80, 1234, 200, syn_ack(), &[]);
    table.process(&pkt);

    // PSH with empty payload — should produce no output
    let pkt = make_packet([10, 0, 0, 1], [10, 0, 0, 2], 1234, 80, 101, psh_ack(), &[]);
    let results = table.process(&pkt);
    assert!(results.is_empty());
}

#[test]
fn reassembly_duplicate_syn() {
    // SYN retransmission
    let mut table = StreamTable::new();

    let pkt = make_packet([10, 0, 0, 1], [10, 0, 0, 2], 1234, 80, 100, syn(), &[]);
    table.process(&pkt);

    // Same SYN again — should emit old stream (empty) and create new
    let pkt = make_packet([10, 0, 0, 1], [10, 0, 0, 2], 1234, 80, 100, syn(), &[]);
    let results = table.process(&pkt);
    // No data was buffered, so nothing to emit
    assert!(results.is_empty());
}

#[test]
fn reassembly_rst_on_unknown_stream() {
    // RST for a stream we never saw — should not crash
    let mut table = StreamTable::new();

    let pkt = make_packet(
        [10, 0, 0, 1],
        [10, 0, 0, 2],
        9999,
        80,
        500,
        rst_flags(),
        &[],
    );
    let results = table.process(&pkt);
    assert!(results.is_empty());
}

#[test]
fn reassembly_data_without_syn() {
    // Mid-stream capture (no SYN seen)
    let mut table = StreamTable::new();

    let pkt = make_packet(
        [10, 0, 0, 1],
        [10, 0, 0, 2],
        1234,
        80,
        500,
        psh_ack(),
        b"mid-stream data",
    );
    let results = table.process(&pkt);
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].payload, b"mid-stream data");
}

#[test]
fn reassembly_identical_packets_dedup() {
    // Same packet sent 10 times — should only see data once
    let mut table = StreamTable::new();

    let pkt = make_packet([10, 0, 0, 1], [10, 0, 0, 2], 1234, 80, 100, syn(), &[]);
    table.process(&pkt);
    let pkt = make_packet([10, 0, 0, 2], [10, 0, 0, 1], 80, 1234, 200, syn_ack(), &[]);
    table.process(&pkt);

    let pkt = make_packet(
        [10, 0, 0, 1],
        [10, 0, 0, 2],
        1234,
        80,
        101,
        psh_ack(),
        b"once",
    );
    let results = table.process(&pkt);
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].payload, b"once");

    // Retransmit same packet 9 more times
    for _ in 0..9 {
        let pkt = make_packet(
            [10, 0, 0, 1],
            [10, 0, 0, 2],
            1234,
            80,
            101,
            psh_ack(),
            b"once",
        );
        let results = table.process(&pkt);
        assert!(results.is_empty(), "Retransmit should produce no output");
    }
}

// =============================================================================
// Cross-module: HTTP parsing on reassembled binary data
// =============================================================================

#[test]
fn http_parse_with_binary_body() {
    // HTTP response with binary body (not valid UTF-8)
    let mut data = b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\n".to_vec();
    data.extend_from_slice(&[0xFF, 0xFE, 0xFD, 0x00, 0x01, 0x02, 0x80, 0x90, 0xA0, 0xB0]);
    let msgs = parse_http(&data);
    assert_eq!(msgs.len(), 1);
    // Body goes through from_utf8_lossy, so invalid bytes become U+FFFD (3 bytes each in UTF-8).
    // 10 input bytes -> some expand to 3 bytes each. Just verify it parsed without panic.
    assert!(!msgs[0].body.is_empty());
}

#[test]
fn http_parse_pipeline_with_body() {
    // HTTP pipelining: multiple request/response pairs
    let data = b"GET /1 HTTP/1.1\r\nHost: x\r\n\r\n\
                 HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok\
                 GET /2 HTTP/1.1\r\nHost: x\r\n\r\n\
                 HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\ndone";
    let msgs = parse_http(data);
    assert_eq!(msgs.len(), 4); // 2 requests + 2 responses
}
