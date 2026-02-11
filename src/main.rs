mod capture;
mod output;
mod protocol;
mod reassembly;

use anyhow::{Context, Result};
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

    let formatter = Formatter::new(cli.json, cli.hex, cli.quiet, cli.http);
    let mut stream_table = StreamTable::new();
    let mut match_count: usize = 0;

    let mut source = if let Some(ref path) = cli.input {
        PacketSource::from_file(path, cli.bpf.as_deref())?
    } else {
        let interface = cli.interface.as_deref().unwrap_or("any");
        PacketSource::live(interface, cli.snaplen, !cli.no_promisc, cli.bpf.as_deref())?
    };

    // Set up pcap output file if requested
    let mut pcap_writer = match &cli.output_file {
        Some(path) => {
            let file = std::fs::File::create(path)
                .context(format!("Failed to create output file: {}", path.display()))?;
            Some(PcapWriter::new(file)?)
        }
        None => None,
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
                    if let Some(ref mut writer) = pcap_writer {
                        let _ = writer.write_packet(packet_data.data, packet_data.timestamp);
                    }
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

/// Minimal pcap file writer (libpcap format).
struct PcapWriter<W: std::io::Write> {
    writer: W,
}

impl<W: std::io::Write> PcapWriter<W> {
    fn new(mut writer: W) -> Result<Self> {
        // Write pcap global header
        let header = PcapGlobalHeader {
            magic: 0xa1b2c3d4,
            version_major: 2,
            version_minor: 4,
            thiszone: 0,
            sigfigs: 0,
            snaplen: 65535,
            network: 1, // LINKTYPE_ETHERNET
        };
        let bytes: &[u8] = unsafe {
            std::slice::from_raw_parts(
                &header as *const PcapGlobalHeader as *const u8,
                std::mem::size_of::<PcapGlobalHeader>(),
            )
        };
        writer.write_all(bytes)?;
        Ok(PcapWriter { writer })
    }

    fn write_packet(&mut self, data: &[u8], timestamp: std::time::SystemTime) -> Result<()> {
        let duration = timestamp
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();

        let pkt_header = PcapPacketHeader {
            ts_sec: duration.as_secs() as u32,
            ts_usec: duration.subsec_micros(),
            incl_len: data.len() as u32,
            orig_len: data.len() as u32,
        };
        let header_bytes: &[u8] = unsafe {
            std::slice::from_raw_parts(
                &pkt_header as *const PcapPacketHeader as *const u8,
                std::mem::size_of::<PcapPacketHeader>(),
            )
        };
        self.writer.write_all(header_bytes)?;
        self.writer.write_all(data)?;
        Ok(())
    }
}

#[repr(C)]
struct PcapGlobalHeader {
    magic: u32,
    version_major: u16,
    version_minor: u16,
    thiszone: i32,
    sigfigs: u32,
    snaplen: u32,
    network: u32,
}

#[repr(C)]
struct PcapPacketHeader {
    ts_sec: u32,
    ts_usec: u32,
    incl_len: u32,
    orig_len: u32,
}
