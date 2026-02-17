mod capture;
mod output;
mod protocol;
mod reassembly;
mod tls;
mod tui;

use anyhow::{Context, Result};
use clap::Parser;
use pcap::Device;
use regex::bytes::Regex;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use capture::PacketSource;
use capture::pcap_writer::PcapWriter;
use output::Formatter;
use reassembly::StreamTable;

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
    #[arg(short = 'B', long)]
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
            Some(Regex::new(&pat)?)
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
            if stop_clone.load(Ordering::Relaxed) {
                // Second Ctrl+C — force exit
                std::process::exit(1);
            }
            stop_clone.store(true, Ordering::Relaxed);
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
            let file = std::fs::File::create(path)
                .context(format!("Failed to create output file: {}", path.display()))?;
            Some(PcapWriter::new(file, link_type.pcap_link_type())?)
        }
        None => None,
    };

    source.for_each_packet(|packet_data| {
        if stop_flag.load(Ordering::Relaxed) {
            return false;
        }

        packets_seen += 1;

        let mut parsed = match protocol::parse_packet(packet_data.data, link_type) {
            Some(p) => p,
            None => return true,
        };
        parsed.timestamp = Some(packet_data.timestamp);

        if !cli.no_reassemble && parsed.is_tcp() {
            for stream_data in stream_table.process(&parsed) {
                // Feed TLS decryptor with deduped, in-order stream data
                if let Some(key) = parsed.stream_key() {
                    let (src_ip, src_port) = direction_src(&parsed, &stream_data.direction);
                    feed_tls_stream(&key, &stream_data.payload, src_ip, src_port, tls_decryptor);

                    let effective_payload =
                        resolve_tls_payload(&key, tls_decryptor, &stream_data.payload);

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
                        h2.process(&key, &effective_payload, h2_dir)
                    } else {
                        vec![]
                    };

                    if !h2_messages.is_empty() {
                        // HTTP/2 messages found — match and display individually
                        let stream_id = key.to_string();
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
                                    use std::io::Write;
                                    let _ = std::io::stdout().flush();
                                }
                                if let Some(ref mut writer) = pcap_writer
                                    && let Err(e) =
                                        writer.write_packet(packet_data.data, packet_data.timestamp)
                                {
                                    eprintln!(
                                        "Warning: failed to write packet to output file: {}",
                                        e
                                    );
                                }
                                match_count += 1;
                            }
                        }
                    } else if is_match(&effective_payload, pattern, cli.invert) {
                        let display_data = reassembly::StreamData {
                            key: stream_data.key,
                            payload: effective_payload,
                            direction: stream_data.direction,
                        };
                        formatter.print_stream(&display_data, pattern);
                        if line_buffered {
                            use std::io::Write;
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
            }
        } else {
            // M4: Skip TLS resolution in no-reassemble path — TLS decryption
            // requires reassembled stream data and won't work per-packet.
            let payload = parsed.payload.clone();
            let match_text = build_match_text(&payload, &parsed, cli.dns);
            if is_match(&match_text, pattern, cli.invert) {
                formatter.print_packet(&parsed, pattern);
                if line_buffered {
                    use std::io::Write;
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

/// Determine the source IP and port for a given direction.
fn direction_src(
    parsed: &protocol::ParsedPacket,
    direction: &reassembly::Direction,
) -> (std::net::IpAddr, u16) {
    match direction {
        reassembly::Direction::Forward => (
            parsed
                .src_ip
                .unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)),
            parsed.src_port.unwrap_or(0),
        ),
        reassembly::Direction::Reverse => (
            parsed
                .dst_ip
                .unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)),
            parsed.dst_port.unwrap_or(0),
        ),
    }
}

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
            if capture_stop.load(Ordering::Relaxed) {
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
                    // Feed TLS with deduped data
                    if let Some(key) = parsed.stream_key() {
                        let (src_ip, src_port) = direction_src(&parsed, &stream_data.direction);
                        feed_tls_stream(
                            &key,
                            &stream_data.payload,
                            src_ip,
                            src_port,
                            &mut tls_decryptor,
                        );
                        let effective_payload =
                            resolve_tls_payload(&key, &mut tls_decryptor, &stream_data.payload);

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
                            h2.process(&key, &effective_payload, h2_dir)
                        } else {
                            vec![]
                        };

                        if !h2_messages.is_empty() {
                            // HTTP/2 messages — match against display text
                            for msg in &h2_messages {
                                let display = msg.display_string();
                                if is_match(display.as_bytes(), &pattern, invert) {
                                    event_id += 1;
                                    let event = tui::event::CaptureEvent::from_h2_messages(
                                        event_id,
                                        &key,
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
                }
            } else {
                let payload = if parsed.is_tcp() {
                    if let Some(key) = parsed.stream_key() {
                        resolve_tls_payload(&key, &mut tls_decryptor, &parsed.payload)
                    } else {
                        parsed.payload.clone()
                    }
                } else {
                    parsed.payload.clone()
                };
                let match_text = build_match_text(&payload, &parsed, dns_mode);
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
    stop_flag.store(true, Ordering::Relaxed);
    match capture_thread.join() {
        Ok(Err(e)) => {
            // TUI exited cleanly but capture had an error — report it
            result.and(Err(e))
        }
        // M5: Handle thread panic
        Err(_) => result.and(Err(anyhow::anyhow!("capture thread panicked"))),
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
