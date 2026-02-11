mod capture;
mod output;
mod protocol;
mod reassembly;

use anyhow::Result;
use clap::Parser;
use pcap::Device;
use regex::Regex;
use std::path::PathBuf;

use capture::PacketSource;
use output::Formatter;
use reassembly::StreamTable;

#[derive(Parser)]
#[command(name = "netgrep", version, about = "Grep for the network, for a post-TLS world")]
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

    /// Reassemble TCP streams before matching (default: true)
    #[arg(long, default_value_t = true)]
    reassemble: bool,

    /// Show hex dump of matched payloads
    #[arg(short = 'x', long)]
    hex: bool,

    /// HTTP-aware mode: parse and match against HTTP request/response fields
    #[arg(long)]
    http: bool,

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

    let formatter = Formatter::new(cli.json, cli.hex, cli.quiet);
    let mut stream_table = StreamTable::new();
    let mut match_count: usize = 0;

    let mut source = if let Some(ref path) = cli.input {
        PacketSource::from_file(path, cli.bpf.as_deref())?
    } else {
        let interface = cli.interface.as_deref().unwrap_or("any");
        PacketSource::live(interface, cli.snaplen, !cli.no_promisc, cli.bpf.as_deref())?
    };

    source.for_each_packet(|packet_data| {
        let parsed = match protocol::parse_packet(packet_data.data) {
            Some(p) => p,
            None => return true,
        };

        if cli.reassemble && parsed.is_tcp() {
            if let Some(stream_data) = stream_table.process(&parsed) {
                let matched = match &pattern {
                    Some(re) => re.is_match(&stream_data.payload_str()) != cli.invert,
                    None => !cli.invert,
                };
                if matched {
                    formatter.print_stream(&stream_data, &pattern);
                    match_count += 1;
                }
            }
        } else {
            let matched = match &pattern {
                Some(re) => re.is_match(&parsed.payload_str()) != cli.invert,
                None => !cli.invert,
            };
            if matched {
                formatter.print_packet(&parsed, &pattern);
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

fn list_interfaces() -> Result<()> {
    let devices = Device::list()?;
    for dev in devices {
        let desc = dev.desc.as_deref().unwrap_or("");
        let addrs: Vec<String> = dev
            .addresses
            .iter()
            .map(|a| a.addr.to_string())
            .collect();
        println!(
            "{:<16} {}  [{}]",
            dev.name,
            desc,
            addrs.join(", ")
        );
    }
    Ok(())
}
