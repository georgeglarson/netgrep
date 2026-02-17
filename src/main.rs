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
    #[arg(short = 's', long, default_value_t = 65535)]
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

    if cli.tui {
        if cli.output_file.is_some() {
            eprintln!("Warning: --output-file is not supported in TUI mode and will be ignored");
        }
        run_tui_mode(&cli, source, tls_decryptor, pattern)
    } else {
        // Install Ctrl+C handler for graceful shutdown
        let stop_flag = Arc::new(AtomicBool::new(false));
        let stop_clone = stop_flag.clone();
        ctrlc::set_handler(move || {
            if stop_clone.load(Ordering::Relaxed) {
                // Second Ctrl+C — force exit
                std::process::exit(1);
            }
            stop_clone.store(true, Ordering::Relaxed);
        })
        .ok();

        run_cli_mode(&cli, &mut source, &mut tls_decryptor, &pattern, &stop_flag)
    }
}

fn run_cli_mode(
    cli: &Cli,
    source: &mut PacketSource,
    tls_decryptor: &mut Option<tls::TlsDecryptor>,
    pattern: &Option<Regex>,
    stop_flag: &Arc<AtomicBool>,
) -> Result<()> {
    let formatter = Formatter::new(cli.json, cli.hex, cli.quiet, cli.http, cli.dns);
    let mut stream_table = StreamTable::new();
    let mut match_count: usize = 0;
    let link_type = source.link_type();

    let mut pcap_writer = match &cli.output_file {
        Some(path) => {
            let file = std::fs::File::create(path)
                .context(format!("Failed to create output file: {}", path.display()))?;
            Some(PcapWriter::new(file)?)
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

        // Feed every TCP packet to TLS decryptor incrementally (before reassembly)
        if parsed.is_tcp() {
            if let Some(decryptor) = tls_decryptor.as_mut() {
                if let (Some(key), Some(src_ip), Some(src_port)) =
                    (parsed.stream_key(), parsed.src_ip, parsed.src_port)
                {
                    decryptor.process_packet(&key, &parsed.payload, src_ip, src_port);
                }
            }
        }

        if !cli.no_reassemble && parsed.is_tcp() {
            if let Some(stream_data) = stream_table.process(&parsed) {
                // Use decrypted plaintext if available, otherwise raw stream data
                let effective_payload = if let Some(decryptor) = tls_decryptor.as_ref() {
                    parsed
                        .stream_key()
                        .and_then(|key| decryptor.get_decrypted(&key))
                        .unwrap_or_else(|| stream_data.payload.clone())
                } else {
                    stream_data.payload.clone()
                };

                let effective_str = String::from_utf8_lossy(&effective_payload);
                let matched = match &pattern {
                    Some(re) => re.is_match(&effective_str) != cli.invert,
                    None => !cli.invert,
                };
                if matched {
                    let display_data = reassembly::StreamData {
                        key: stream_data.key,
                        payload: effective_payload,
                    };
                    formatter.print_stream(&display_data, pattern);
                    if let Some(ref mut writer) = pcap_writer {
                        let _ = writer.write_packet(packet_data.data, packet_data.timestamp);
                    }
                    match_count += 1;
                }
            }
        } else {
            let match_text = if cli.dns
                && parsed.transport == protocol::Transport::Udp
                && parsed.is_dns_port()
            {
                protocol::dns::parse_dns(&parsed.payload)
                    .map(|info| info.display_string())
                    .unwrap_or_else(|| parsed.payload_str())
            } else {
                parsed.payload_str()
            };
            let matched = match &pattern {
                Some(re) => re.is_match(&match_text) != cli.invert,
                None => !cli.invert,
            };
            if matched {
                formatter.print_packet(&parsed, pattern);
                if let Some(ref mut writer) = pcap_writer {
                    let _ = writer.write_packet(packet_data.data, packet_data.timestamp);
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
    let http_mode = cli.http;
    let count_limit = cli.count;

    let capture_thread = std::thread::spawn(move || {
        let mut stream_table = StreamTable::new();
        let mut event_id: usize = 0;
        let mut match_count: usize = 0;

        let _ = source.for_each_packet(|packet_data| {
            if capture_stop.load(Ordering::Relaxed) {
                return false;
            }

            capture_seen.fetch_add(1, Ordering::Relaxed);

            let parsed = match protocol::parse_packet(packet_data.data, link_type) {
                Some(p) => p,
                None => return true,
            };

            // Feed TCP packets to TLS decryptor
            if parsed.is_tcp() {
                if let Some(ref mut decryptor) = tls_decryptor {
                    if let (Some(key), Some(src_ip), Some(src_port)) =
                        (parsed.stream_key(), parsed.src_ip, parsed.src_port)
                    {
                        decryptor.process_packet(&key, &parsed.payload, src_ip, src_port);
                    }
                }
            }

            if reassemble && parsed.is_tcp() {
                if let Some(stream_data) = stream_table.process(&parsed) {
                    let effective_payload = if let Some(ref decryptor) = tls_decryptor {
                        parsed
                            .stream_key()
                            .and_then(|key| decryptor.get_decrypted(&key))
                            .unwrap_or_else(|| stream_data.payload.clone())
                    } else {
                        stream_data.payload.clone()
                    };

                    let effective_str = String::from_utf8_lossy(&effective_payload);
                    let matched = match &pattern {
                        Some(re) => re.is_match(&effective_str) != invert,
                        None => !invert,
                    };
                    if matched {
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
                let match_text = if dns_mode
                    && parsed.transport == protocol::Transport::Udp
                    && parsed.is_dns_port()
                {
                    protocol::dns::parse_dns(&parsed.payload)
                        .map(|info| info.display_string())
                        .unwrap_or_else(|| parsed.payload_str())
                } else {
                    parsed.payload_str()
                };
                let matched = match &pattern {
                    Some(re) => re.is_match(&match_text) != invert,
                    None => !invert,
                };
                if matched {
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
        });
    });

    // Run TUI on main thread
    let result = tui::run_tui(rx, packets_seen, stop_flag.clone());

    // Ensure capture thread stops
    stop_flag.store(true, Ordering::Relaxed);
    let _ = capture_thread.join();

    result
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
