#![allow(clippy::uninlined_format_args)]

use anyhow::{Context, Result};
use clap::Parser;
use pcap::Device;
use regex::bytes::Regex;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use netgrep::capture::PacketSource;
use netgrep::capture::pcap_writer::PcapWriter;
use netgrep::output::Formatter;
use netgrep::protocol;
use netgrep::reassembly::{self, StreamTable};
use netgrep::tls;
use netgrep::tui;

#[derive(Parser)]
#[command(
    name = "netgrep",
    version,
    about = "Grep for the network, for a post-TLS world"
)]
struct Cli {
    /// Regex pattern to match against packet payloads / reassembled streams
    pattern: Option<String>,

    /// BPF filter expression (same syntax as tcpdump)
    #[arg(short = 'F', long)]
    bpf: Option<String>,

    /// Network interface to capture on
    #[arg(short = 'd', long)]
    interface: Option<String>,

    /// Read from pcap/pcapng file instead of live capture
    #[arg(short = 'I', long)]
    input: Option<PathBuf>,

    /// Case-insensitive matching
    #[arg(short = 'i', long)]
    ignore_case: bool,

    /// Invert match (show non-matching packets)
    #[arg(short = 'v', long)]
    invert: bool,

    /// Output as JSON
    #[arg(long, conflicts_with = "hex")]
    json: bool,

    /// Capture N matches then exit (1–1048576)
    #[arg(short = 'n', long, value_parser = clap::value_parser!(u64).range(1..=1048576))]
    count: Option<u64>,

    /// Don't use promiscuous mode
    #[arg(short = 'p', long)]
    no_promisc: bool,

    /// Disable TCP stream reassembly (match individual packets instead)
    #[arg(long)]
    no_reassemble: bool,

    /// Show hex dump of matched payloads
    #[arg(short = 'x', long)]
    hex: bool,

    /// HTTP-aware mode: parse and match against HTTP request/response fields
    #[arg(long)]
    http: bool,

    /// DNS-aware mode: parse and display DNS queries/responses
    #[arg(long)]
    dns: bool,

    /// SSLKEYLOGFILE path for TLS decryption
    #[arg(long, env = "SSLKEYLOGFILE")]
    keylog: Option<PathBuf>,

    /// Quiet mode (payload only, no packet headers)
    #[arg(short = 'q', long)]
    quiet: bool,

    /// List available interfaces and exit
    #[arg(short = 'L', long)]
    list_interfaces: bool,

    /// Snap length (bytes to capture per packet)
    #[arg(short = 's', long, default_value_t = 65535, value_parser = clap::value_parser!(i32).range(1..=65535))]
    snaplen: i32,

    /// Write the triggering packet (not the full stream) to pcap file on match
    #[arg(short = 'O', long)]
    output_file: Option<PathBuf>,

    /// Interactive TUI mode
    #[arg(long)]
    tui: bool,

    /// Kernel buffer size in KiB for live capture (default: OS default, typically 2048)
    #[arg(short = 'B', long, value_parser = clap::value_parser!(i32).range(1..=2_097_151))]
    buffer_size: Option<i32>,

    /// Line-buffered output (flush stdout after each match)
    #[arg(short = 'l', long)]
    line_buffered: bool,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    if cli.list_interfaces {
        list_interfaces()?;
        return Ok(());
    }

    let pattern = match &cli.pattern {
        Some(p) => {
            let pat = if cli.ignore_case {
                format!("(?i){}", p)
            } else {
                p.clone()
            };
            // M11: Limit compiled regex size to prevent ReDoS via
            // pathological patterns that cause exponential memory usage.
            Some(
                regex::bytes::RegexBuilder::new(&pat)
                    .size_limit(10 * 1024 * 1024)
                    .build()
                    .context(format!("Invalid regex pattern: {}", p))?,
            )
        }
        None => None,
    };

    let mut source = if let Some(ref path) = cli.input {
        PacketSource::from_file(path, cli.bpf.as_deref())?
    } else {
        PacketSource::live(
            cli.interface.as_deref(),
            cli.snaplen,
            !cli.no_promisc,
            cli.bpf.as_deref(),
            cli.buffer_size,
        )?
    };

    let mut tls_decryptor = match &cli.keylog {
        Some(path) => {
            let keylog = tls::keylog::KeyLog::from_file(path)?;
            Some(tls::TlsDecryptor::new(keylog))
        }
        None => None,
    };

    if cli.invert && cli.pattern.is_none() {
        eprintln!("Warning: -v/--invert with no pattern will match nothing");
    }
    if cli.http && cli.no_reassemble {
        eprintln!(
            "Warning: --http requires TCP reassembly; it will be ignored with --no-reassemble"
        );
    }
    if cli.keylog.is_some() && cli.no_reassemble {
        eprintln!(
            "Warning: --keylog requires TCP reassembly for TLS decryption; \
             it will not work with --no-reassemble"
        );
    }
    // L3: Warn when --dns + --no-reassemble (DNS over TCP won't work)
    if cli.dns && cli.no_reassemble {
        eprintln!(
            "Warning: --dns with --no-reassemble will only match single-packet DNS (typically UDP)"
        );
    }
    // L2: Warn when --tui combined with incompatible output flags
    if cli.tui {
        if cli.json {
            eprintln!("Warning: --json is ignored in TUI mode");
        }
        if cli.hex {
            eprintln!("Warning: --hex is ignored in TUI mode");
        }
        if cli.quiet {
            eprintln!("Warning: --quiet is ignored in TUI mode");
        }
    }

    // --http is a no-op without reassembly; disable it to avoid confusion
    let http_mode = cli.http && !cli.no_reassemble;

    if cli.tui {
        if cli.output_file.is_some() {
            eprintln!("Warning: --output-file is not supported in TUI mode and will be ignored");
        }
        run_tui_mode(&cli, source, tls_decryptor, pattern, http_mode)
    } else {
        // Install Ctrl+C handler for graceful shutdown
        let stop_flag = Arc::new(AtomicBool::new(false));
        let stop_clone = stop_flag.clone();
        if let Err(e) = ctrlc::set_handler(move || {
            if stop_clone.load(Ordering::Acquire) {
                // Second Ctrl+C — force exit.
                // M10: process::exit bypasses Drop impls, so pcap writers won't
                // flush and TLS key material won't be zeroized. Acceptable because
                // the user is explicitly requesting immediate termination.
                std::process::exit(1);
            }
            stop_clone.store(true, Ordering::Release);
        }) {
            eprintln!("Warning: failed to install Ctrl+C handler: {}", e);
        }

        run_cli_mode(
            &cli,
            &mut source,
            &mut tls_decryptor,
            &pattern,
            &stop_flag,
            http_mode,
        )
    }
}

/// Feed reassembled (deduped, in-order) stream data to the TLS decryptor.
/// This is called AFTER TCP reassembly to avoid feeding retransmissions.
fn feed_tls_stream(
    key: &protocol::StreamKey,
    payload: &[u8],
    src_ip: std::net::IpAddr,
    src_port: u16,
    decryptor: &mut Option<tls::TlsDecryptor>,
) {
    if let Some(decryptor) = decryptor.as_mut() {
        decryptor.process_packet(key, payload, src_ip, src_port);
    }
}

/// Get decrypted TLS payload if available, otherwise return the fallback payload.
fn resolve_tls_payload(
    key: &protocol::StreamKey,
    decryptor: &mut Option<tls::TlsDecryptor>,
    fallback: &[u8],
) -> Vec<u8> {
    if let Some(decryptor) = decryptor.as_mut() {
        return decryptor
            .get_decrypted(key)
            .unwrap_or_else(|| fallback.to_vec());
    }
    fallback.to_vec()
}

/// Build a match-text string, using DNS display format when in DNS mode.
fn build_match_text(payload: &[u8], parsed: &protocol::ParsedPacket, dns_mode: bool) -> Vec<u8> {
    if dns_mode && parsed.is_dns_port() {
        let dns_data = protocol::dns::strip_tcp_prefix(payload, parsed.is_tcp());
        if let Some(info) = protocol::dns::parse_dns(dns_data) {
            return info.display_string().into_bytes();
        }
    }
    payload.to_vec()
}

/// Check whether payload matches the pattern, respecting invert flag.
fn is_match(payload: &[u8], pattern: &Option<Regex>, invert: bool) -> bool {
    match pattern {
        Some(re) => re.is_match(payload) != invert,
        None => !invert,
    }
}

fn run_cli_mode(
    cli: &Cli,
    source: &mut PacketSource,
    tls_decryptor: &mut Option<tls::TlsDecryptor>,
    pattern: &Option<Regex>,
    stop_flag: &Arc<AtomicBool>,
    http_mode: bool,
) -> Result<()> {
    let formatter = Formatter::new(cli.json, cli.hex, cli.quiet, http_mode, cli.dns);
    let mut stream_table = StreamTable::new();
    let mut match_count: u64 = 0;
    let mut packets_seen: u64 = 0;
    let link_type = source.link_type();
    let line_buffered = cli.line_buffered;
    let mut h2_tracker = if http_mode {
        Some(protocol::http2::H2Tracker::new())
    } else {
        None
    };

    let mut pcap_writer = match &cli.output_file {
        Some(path) => {
            let file = {
                let mut opts = std::fs::OpenOptions::new();
                opts.write(true).create_new(true);
                #[cfg(unix)]
                {
                    use std::os::unix::fs::OpenOptionsExt;
                    opts.mode(0o600);
                }
                opts.open(path).context(format!(
                    "Failed to create output file (must not already exist): {}",
                    path.display()
                ))?
            };
            Some(PcapWriter::new(file, link_type.pcap_link_type())?)
        }
        None => None,
    };

    // L9: Import once for all flush() calls below.
    use std::io::Write as _;

    source.for_each_packet(|packet_data| {
        if stop_flag.load(Ordering::Acquire) {
            return false;
        }

        packets_seen = packets_seen.wrapping_add(1);

        let mut parsed = match protocol::parse_packet(packet_data.data, link_type) {
            Some(p) => p,
            None => return true,
        };
        parsed.timestamp = Some(packet_data.timestamp);

        if !cli.no_reassemble && parsed.is_tcp() {
            for stream_data in stream_table.process(&parsed) {
                // Use stream_data.key (not parsed.stream_key()) so evicted
                // streams get the correct key for TLS/H2 processing.
                let (src_ip, src_port) = stream_data.src_addr;
                feed_tls_stream(
                    &stream_data.key,
                    &stream_data.payload,
                    src_ip,
                    src_port,
                    tls_decryptor,
                );

                let effective_payload =
                    resolve_tls_payload(&stream_data.key, tls_decryptor, &stream_data.payload);

                // Try HTTP/2 parsing if in http mode
                let h2_messages = if let Some(ref mut h2) = h2_tracker {
                    let h2_dir = match stream_data.direction {
                        reassembly::Direction::Forward => {
                            protocol::http2::H2Direction::ClientToServer
                        }
                        reassembly::Direction::Reverse => {
                            protocol::http2::H2Direction::ServerToClient
                        }
                    };
                    h2.process(&stream_data.key, &effective_payload, h2_dir)
                } else {
                    vec![]
                };

                if !h2_messages.is_empty() {
                    // HTTP/2 messages found — match and display individually
                    let stream_id = stream_data.key.to_string();
                    for msg in &h2_messages {
                        // M2: Check count limit inside H2 message loop
                        if let Some(n) = cli.count
                            && match_count >= n
                        {
                            break;
                        }
                        let display = msg.display_string();
                        if is_match(display.as_bytes(), pattern, cli.invert) {
                            if cli.json {
                                formatter.print_http_json(&stream_id, msg);
                            } else {
                                formatter.print_http_text(&stream_id, msg, pattern);
                            }
                            if line_buffered {
                                let _ = std::io::stdout().flush();
                            }
                            if let Some(ref mut writer) = pcap_writer
                                && let Err(e) =
                                    writer.write_packet(packet_data.data, packet_data.timestamp)
                            {
                                eprintln!("Warning: failed to write packet to output file: {}", e);
                            }
                            match_count += 1;
                        }
                    }
                } else if is_match(&effective_payload, pattern, cli.invert) {
                    let display_data = reassembly::StreamData {
                        key: stream_data.key,
                        payload: effective_payload,
                        direction: stream_data.direction,
                        src_addr: stream_data.src_addr,
                    };
                    formatter.print_stream(&display_data, pattern);
                    if line_buffered {
                        let _ = std::io::stdout().flush();
                    }
                    if let Some(ref mut writer) = pcap_writer
                        && let Err(e) = writer.write_packet(packet_data.data, packet_data.timestamp)
                    {
                        eprintln!("Warning: failed to write packet to output file: {}", e);
                    }
                    match_count += 1;
                }
            }

            // Clean up TLS state when stream is closed (FIN/RST/eviction)
            // to zeroize key material promptly instead of waiting for LRU eviction.
            if let Some(key) = parsed.stream_key() {
                if !stream_table.contains(&key) {
                    if let Some(d) = tls_decryptor.as_mut() {
                        d.remove_connection(&key);
                    }
                }
            }
        } else {
            // M4: Skip TLS resolution in no-reassemble path — TLS decryption
            // requires reassembled stream data and won't work per-packet.
            // L10: Use &parsed.payload directly instead of cloning.
            let match_text = build_match_text(&parsed.payload, &parsed, cli.dns);
            if is_match(&match_text, pattern, cli.invert) {
                formatter.print_packet(&parsed, pattern);
                if line_buffered {
                    let _ = std::io::stdout().flush();
                }
                if let Some(ref mut writer) = pcap_writer
                    && let Err(e) = writer.write_packet(packet_data.data, packet_data.timestamp)
                {
                    eprintln!("Warning: failed to write packet to output file: {}", e);
                }
                match_count += 1;
            }
        }

        match cli.count {
            Some(n) => match_count < n,
            None => true,
        }
    })?;

    // Print capture statistics
    eprintln!("{} packets seen, {} matches", packets_seen, match_count);

    Ok(())
}

// M12: The CLI and TUI capture loops share structural similarities (stream
// reassembly, TLS decryption, HTTP/2 parsing, pattern matching) but differ in
// output handling (stdout vs channel events). A shared capture-loop function
// parameterized by an output sink would reduce duplication — left as a future
// refactoring opportunity to avoid destabilizing the capture paths.
fn run_tui_mode(
    cli: &Cli,
    mut source: PacketSource,
    mut tls_decryptor: Option<tls::TlsDecryptor>,
    pattern: Option<Regex>,
    http_mode: bool,
) -> Result<()> {
    // M1: Use bounded channel to apply backpressure when TUI can't keep up
    let (tx, rx) = crossbeam_channel::bounded::<tui::event::CaptureEvent>(10_000);
    let stop_flag = Arc::new(AtomicBool::new(false));
    let packets_seen = Arc::new(AtomicU64::new(0));

    let link_type = source.link_type();
    let capture_stop = stop_flag.clone();
    let capture_seen = packets_seen.clone();
    let reassemble = !cli.no_reassemble;
    let invert = cli.invert;
    let dns_mode = cli.dns;
    let count_limit = cli.count;

    let capture_thread = std::thread::spawn(move || -> Result<()> {
        let mut stream_table = StreamTable::new();
        let mut event_id: usize = 0;
        let mut match_count: u64 = 0;
        let mut h2_tracker = if http_mode {
            Some(protocol::http2::H2Tracker::new())
        } else {
            None
        };

        source.for_each_packet(|packet_data| {
            if capture_stop.load(Ordering::Acquire) {
                return false;
            }

            capture_seen.fetch_add(1, Ordering::Relaxed);

            let mut parsed = match protocol::parse_packet(packet_data.data, link_type) {
                Some(p) => p,
                None => return true,
            };
            parsed.timestamp = Some(packet_data.timestamp);

            if reassemble && parsed.is_tcp() {
                for stream_data in stream_table.process(&parsed) {
                    // Use stream_data.key (not parsed.stream_key()) so evicted
                    // streams get the correct key for TLS/H2 processing.
                    let (src_ip, src_port) = stream_data.src_addr;
                    feed_tls_stream(
                        &stream_data.key,
                        &stream_data.payload,
                        src_ip,
                        src_port,
                        &mut tls_decryptor,
                    );
                    let effective_payload = resolve_tls_payload(
                        &stream_data.key,
                        &mut tls_decryptor,
                        &stream_data.payload,
                    );

                    // Try HTTP/2 parsing
                    let h2_messages = if let Some(ref mut h2) = h2_tracker {
                        let h2_dir = match stream_data.direction {
                            reassembly::Direction::Forward => {
                                protocol::http2::H2Direction::ClientToServer
                            }
                            reassembly::Direction::Reverse => {
                                protocol::http2::H2Direction::ServerToClient
                            }
                        };
                        h2.process(&stream_data.key, &effective_payload, h2_dir)
                    } else {
                        vec![]
                    };

                    if !h2_messages.is_empty() {
                        // HTTP/2 messages — match against display text
                        for msg in &h2_messages {
                            // M3: Check count limit inside H2 message loop
                            if let Some(n) = count_limit
                                && match_count >= n
                            {
                                break;
                            }
                            let display = msg.display_string();
                            if is_match(display.as_bytes(), &pattern, invert) {
                                event_id += 1;
                                let event = tui::event::CaptureEvent::from_h2_messages(
                                    event_id,
                                    &stream_data.key,
                                    std::slice::from_ref(msg),
                                );
                                if tx.send(event).is_err() {
                                    return false;
                                }
                                match_count += 1;
                            }
                        }
                    } else if is_match(&effective_payload, &pattern, invert) {
                        event_id += 1;
                        let display_data = reassembly::StreamData {
                            key: stream_data.key,
                            payload: effective_payload,
                            direction: stream_data.direction,
                            src_addr: stream_data.src_addr,
                        };
                        let event = tui::event::CaptureEvent::from_stream(
                            event_id,
                            &display_data,
                            http_mode,
                        );
                        if tx.send(event).is_err() {
                            return false;
                        }
                        match_count += 1;
                    }
                }

                // Clean up TLS state when stream is closed (FIN/RST/eviction)
                if let Some(key) = parsed.stream_key() {
                    if !stream_table.contains(&key) {
                        if let Some(d) = tls_decryptor.as_mut() {
                            d.remove_connection(&key);
                        }
                    }
                }
            } else {
                // M1/M2: Skip TLS resolution in no-reassemble path — TLS decryption
                // requires reassembled stream data and won't work per-packet.
                // L10: Use &parsed.payload directly instead of cloning.
                let match_text = build_match_text(&parsed.payload, &parsed, dns_mode);
                if is_match(&match_text, &pattern, invert) {
                    event_id += 1;
                    let event = tui::event::CaptureEvent::from_packet(event_id, &parsed, dns_mode);
                    if tx.send(event).is_err() {
                        return false;
                    }
                    match_count += 1;
                }
            }

            match count_limit {
                Some(n) => match_count < n,
                None => true,
            }
        })
    });

    // Run TUI on main thread
    let result = tui::run_tui(rx, packets_seen, stop_flag.clone());

    // Ensure capture thread stops
    stop_flag.store(true, Ordering::Release);
    match capture_thread.join() {
        Ok(Err(capture_err)) => {
            // TUI exited cleanly but capture had an error — chain it
            match result {
                Ok(()) => Err(capture_err),
                Err(tui_err) => {
                    Err(tui_err.context(format!("capture thread also failed: {capture_err}")))
                }
            }
        }
        // M5: Handle thread panic — extract message for debuggability
        Err(e) => {
            let msg = e
                .downcast_ref::<String>()
                .map(|s| s.as_str())
                .or_else(|| e.downcast_ref::<&str>().copied())
                .unwrap_or("unknown cause");
            result.and(Err(anyhow::anyhow!("capture thread panicked: {msg}")))
        }
        Ok(Ok(())) => result,
    }
}

fn list_interfaces() -> Result<()> {
    let devices = Device::list()?;
    for dev in devices {
        let desc = dev.desc.as_deref().unwrap_or("");
        let addrs: Vec<String> = dev.addresses.iter().map(|a| a.addr.to_string()).collect();
        println!("{:<16} {}  [{}]", dev.name, desc, addrs.join(", "));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use netgrep::protocol::{ParsedPacket, Transport};
    use std::net::{IpAddr, Ipv4Addr};

    fn make_packet(
        src_port: Option<u16>,
        dst_port: Option<u16>,
        transport: Transport,
        payload: &[u8],
    ) -> ParsedPacket {
        ParsedPacket {
            src_ip: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            dst_ip: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            src_port,
            dst_port,
            transport,
            payload: payload.to_vec(),
            tcp_flags: None,
            seq: None,
            vlan_id: None,
            icmp_type: None,
            icmp_code: None,
            timestamp: None,
        }
    }

    // -- is_match tests --

    #[test]
    fn is_match_pattern_matches() {
        let re = Some(Regex::new("hello").unwrap());
        assert!(is_match(b"say hello world", &re, false));
    }

    #[test]
    fn is_match_pattern_no_match() {
        let re = Some(Regex::new("hello").unwrap());
        assert!(!is_match(b"goodbye world", &re, false));
    }

    #[test]
    fn is_match_invert_true_match() {
        let re = Some(Regex::new("hello").unwrap());
        // Invert: match becomes false
        assert!(!is_match(b"hello world", &re, true));
    }

    #[test]
    fn is_match_invert_true_no_match() {
        let re = Some(Regex::new("hello").unwrap());
        // Invert: no match becomes true
        assert!(is_match(b"goodbye world", &re, true));
    }

    #[test]
    fn is_match_none_pattern() {
        assert!(is_match(b"anything", &None, false));
    }

    #[test]
    fn is_match_none_pattern_invert() {
        // No pattern + invert = match nothing
        assert!(!is_match(b"anything", &None, true));
    }

    #[test]
    fn is_match_empty_payload() {
        let re = Some(Regex::new("hello").unwrap());
        assert!(!is_match(b"", &re, false));
    }

    #[test]
    fn is_match_binary_data() {
        let re = Some(Regex::new(r"\x00\x01").unwrap());
        assert!(is_match(&[0x00, 0x01, 0x02], &re, false));
    }

    // -- build_match_text tests --

    #[test]
    fn build_match_text_non_dns_port() {
        let pkt = make_packet(Some(8080), Some(80), Transport::Tcp, b"hello");
        let result = build_match_text(b"hello", &pkt, true);
        assert_eq!(result, b"hello");
    }

    #[test]
    fn build_match_text_dns_mode_false() {
        let pkt = make_packet(Some(53), Some(1234), Transport::Udp, b"payload");
        let result = build_match_text(b"payload", &pkt, false);
        assert_eq!(result, b"payload");
    }

    #[test]
    fn build_match_text_dns_port_invalid_dns() {
        let pkt = make_packet(Some(53), Some(1234), Transport::Udp, b"not-dns");
        // Invalid DNS payload should fall back to raw bytes
        let result = build_match_text(b"not-dns", &pkt, true);
        assert_eq!(result, b"not-dns");
    }

    #[test]
    fn build_match_text_dns_query_valid() {
        // Build a minimal DNS query for "example.com" A record
        use simple_dns::{CLASS, Name, Packet, QCLASS, QTYPE, Question, TYPE};
        let mut pkt_dns = Packet::new_query(0x1234);
        pkt_dns.questions.push(Question::new(
            Name::new("example.com").unwrap(),
            QTYPE::TYPE(TYPE::A),
            QCLASS::CLASS(CLASS::IN),
            false,
        ));
        let wire = pkt_dns.build_bytes_vec().unwrap();

        let parsed = make_packet(Some(1234), Some(53), Transport::Udp, &wire);
        let result = build_match_text(&wire, &parsed, true);
        let result_str = String::from_utf8_lossy(&result);
        assert!(result_str.contains("example.com"), "got: {}", result_str);
    }

    #[test]
    fn build_match_text_tcp_dns_with_prefix() {
        // TCP DNS has a 2-byte length prefix
        use simple_dns::{CLASS, Name, Packet, QCLASS, QTYPE, Question, TYPE};
        let mut pkt_dns = Packet::new_query(0x5678);
        pkt_dns.questions.push(Question::new(
            Name::new("test.org").unwrap(),
            QTYPE::TYPE(TYPE::A),
            QCLASS::CLASS(CLASS::IN),
            false,
        ));
        let wire = pkt_dns.build_bytes_vec().unwrap();

        // Prepend 2-byte length prefix for TCP
        let mut tcp_wire = Vec::new();
        tcp_wire.extend_from_slice(&(wire.len() as u16).to_be_bytes());
        tcp_wire.extend_from_slice(&wire);

        let parsed = make_packet(Some(1234), Some(53), Transport::Tcp, &tcp_wire);
        let result = build_match_text(&tcp_wire, &parsed, true);
        let result_str = String::from_utf8_lossy(&result);
        assert!(result_str.contains("test.org"), "got: {}", result_str);
    }

    // -- feed_tls_stream tests --

    #[test]
    fn feed_tls_stream_none_decryptor_is_noop() {
        let key = protocol::StreamKey::new(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            1234,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            443,
        );
        let mut decryptor: Option<tls::TlsDecryptor> = None;
        // Should not panic
        feed_tls_stream(
            &key,
            b"data",
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            1234,
            &mut decryptor,
        );
    }

    // -- resolve_tls_payload tests --

    #[test]
    fn resolve_tls_payload_none_decryptor_returns_fallback() {
        let key = protocol::StreamKey::new(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            1234,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            443,
        );
        let mut decryptor: Option<tls::TlsDecryptor> = None;
        let result = resolve_tls_payload(&key, &mut decryptor, b"fallback");
        assert_eq!(result, b"fallback");
    }
}
