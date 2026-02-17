mod capture;
mod output;
mod protocol;
mod reassembly;
mod tls;
mod tui;

use anyhow::{Context, Result};
use clap::Parser;
use pcap::Device;
use regex::Regex;
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
    #[arg(long)]
    json: bool,

    /// Capture N packets then exit
    #[arg(short = 'n', long)]
    count: Option<usize>,

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

    /// Write matched packets to pcap file
    #[arg(short = 'O', long)]
    output_file: Option<PathBuf>,

    /// Interactive TUI mode
    #[arg(long)]
    tui: bool,
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

/// Feed a TCP packet's payload to the TLS decryptor (if present).
fn feed_tls(parsed: &protocol::ParsedPacket, decryptor: &mut Option<tls::TlsDecryptor>) {
    if parsed.is_tcp() {
        if let Some(decryptor) = decryptor.as_mut() {
            if let (Some(key), Some(src_ip), Some(src_port)) =
                (parsed.stream_key(), parsed.src_ip, parsed.src_port)
            {
                decryptor.process_packet(&key, &parsed.payload, src_ip, src_port);
            }
        }
    }
}

/// Get decrypted TLS payload if available, otherwise return the fallback payload.
fn resolve_tls_payload(
    parsed: &protocol::ParsedPacket,
    decryptor: &mut Option<tls::TlsDecryptor>,
    fallback: &[u8],
) -> Vec<u8> {
    if parsed.is_tcp() {
        if let Some(decryptor) = decryptor.as_mut() {
            return parsed
                .stream_key()
                .and_then(|key| decryptor.get_decrypted(&key))
                .unwrap_or_else(|| fallback.to_vec());
        }
    }
    fallback.to_vec()
}

/// Build a match-text string, using DNS display format when in DNS mode.
fn build_match_text(payload: &[u8], parsed: &protocol::ParsedPacket, dns_mode: bool) -> String {
    if dns_mode && parsed.is_dns_port() {
        let dns_data = dns_payload(payload, parsed.is_tcp());
        if let Some(info) = protocol::dns::parse_dns(dns_data) {
            return info.display_string();
        }
    }
    String::from_utf8_lossy(payload).into_owned()
}

/// Strip the 2-byte TCP DNS length prefix if this is a TCP packet.
/// DNS over TCP prepends a u16 length before the DNS message.
fn dns_payload(payload: &[u8], is_tcp: bool) -> &[u8] {
    if is_tcp && payload.len() > 2 {
        let dns_len = u16::from_be_bytes([payload[0], payload[1]]) as usize;
        if dns_len + 2 <= payload.len() {
            return &payload[2..2 + dns_len];
        }
    }
    payload
}

/// Check whether text matches the pattern, respecting invert flag.
fn is_match(text: &str, pattern: &Option<Regex>, invert: bool) -> bool {
    match pattern {
        Some(re) => re.is_match(text) != invert,
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
    let mut match_count: usize = 0;
    let link_type = source.link_type();

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

        let parsed = match protocol::parse_packet(packet_data.data, link_type) {
            Some(p) => p,
            None => return true,
        };

        feed_tls(&parsed, tls_decryptor);

        if !cli.no_reassemble && parsed.is_tcp() {
            if let Some(stream_data) = stream_table.process(&parsed) {
                let effective_payload =
                    resolve_tls_payload(&parsed, tls_decryptor, &stream_data.payload);
                let effective_str = String::from_utf8_lossy(&effective_payload);
                if is_match(&effective_str, pattern, cli.invert) {
                    let display_data = reassembly::StreamData {
                        key: stream_data.key,
                        payload: effective_payload,
                    };
                    formatter.print_stream(&display_data, pattern);
                    if let Some(ref mut writer) = pcap_writer {
                        if let Err(e) = writer.write_packet(packet_data.data, packet_data.timestamp)
                        {
                            eprintln!("Warning: failed to write packet to output file: {}", e);
                        }
                    }
                    match_count += 1;
                }
            }
        } else {
            let payload = resolve_tls_payload(&parsed, tls_decryptor, &parsed.payload);
            let match_text = build_match_text(&payload, &parsed, cli.dns);
            if is_match(&match_text, pattern, cli.invert) {
                formatter.print_packet(&parsed, pattern);
                if let Some(ref mut writer) = pcap_writer {
                    if let Err(e) = writer.write_packet(packet_data.data, packet_data.timestamp) {
                        eprintln!("Warning: failed to write packet to output file: {}", e);
                    }
                }
                match_count += 1;
            }
        }

        match cli.count {
            Some(n) => match_count < n,
            None => true,
        }
    })?;

    Ok(())
}

fn run_tui_mode(
    cli: &Cli,
    mut source: PacketSource,
    mut tls_decryptor: Option<tls::TlsDecryptor>,
    pattern: Option<Regex>,
    http_mode: bool,
) -> Result<()> {
    let (tx, rx) = crossbeam_channel::unbounded::<tui::event::CaptureEvent>();
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
        let mut match_count: usize = 0;

        source.for_each_packet(|packet_data| {
            if capture_stop.load(Ordering::Relaxed) {
                return false;
            }

            capture_seen.fetch_add(1, Ordering::Relaxed);

            let parsed = match protocol::parse_packet(packet_data.data, link_type) {
                Some(p) => p,
                None => return true,
            };

            feed_tls(&parsed, &mut tls_decryptor);

            if reassemble && parsed.is_tcp() {
                if let Some(stream_data) = stream_table.process(&parsed) {
                    let effective_payload =
                        resolve_tls_payload(&parsed, &mut tls_decryptor, &stream_data.payload);
                    let effective_str = String::from_utf8_lossy(&effective_payload);
                    if is_match(&effective_str, &pattern, invert) {
                        event_id += 1;
                        let display_data = reassembly::StreamData {
                            key: stream_data.key,
                            payload: effective_payload,
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
            } else {
                let payload = resolve_tls_payload(&parsed, &mut tls_decryptor, &parsed.payload);
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
        _ => result,
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
