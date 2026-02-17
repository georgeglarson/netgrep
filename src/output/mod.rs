use colored::Colorize;
use regex::Regex;
use serde_json::json;

use crate::protocol::dns::{self, DnsInfo};
use crate::protocol::http::HttpMessage;
use crate::protocol::{ParsedPacket, Transport};
use crate::reassembly::StreamData;

pub struct Formatter {
    json: bool,
    hex: bool,
    quiet: bool,
    http: bool,
    dns: bool,
}

impl Formatter {
    pub fn new(json: bool, hex: bool, quiet: bool, http: bool, dns: bool) -> Self {
        Formatter {
            json,
            hex,
            quiet,
            http,
            dns,
        }
    }

    pub fn print_packet(&self, packet: &ParsedPacket, pattern: &Option<Regex>) {
        if self.dns && packet.transport == Transport::Udp && packet.is_dns_port() {
            if let Some(info) = dns::parse_dns(&packet.payload) {
                if self.json {
                    self.print_dns_json(packet, &info);
                } else {
                    self.print_dns_text(packet, &info, pattern);
                }
                return;
            }
        }

        if self.json {
            self.print_packet_json(packet);
        } else {
            self.print_packet_text(packet, pattern);
        }
    }

    pub fn print_stream(&self, stream: &StreamData, pattern: &Option<Regex>) {
        if self.http {
            let messages = crate::protocol::http::parse_http(&stream.payload);
            if !messages.is_empty() {
                for msg in &messages {
                    if self.json {
                        self.print_http_json(&stream.key.to_string(), msg);
                    } else {
                        self.print_http_text(&stream.key.to_string(), msg, pattern);
                    }
                }
                return;
            }
        }

        if self.json {
            self.print_stream_json(stream);
        } else {
            self.print_stream_text(stream, pattern);
        }
    }

    fn print_packet_text(&self, packet: &ParsedPacket, pattern: &Option<Regex>) {
        if !self.quiet {
            let proto = format!("{:?}", packet.transport);
            let src = format!(
                "{}:{}",
                packet.src_ip.map(|i| i.to_string()).unwrap_or_default(),
                packet.src_port.unwrap_or(0)
            );
            let dst = format!(
                "{}:{}",
                packet.dst_ip.map(|i| i.to_string()).unwrap_or_default(),
                packet.dst_port.unwrap_or(0)
            );
            eprintln!(
                "{} {} {} {} ({} bytes)",
                proto.blue(),
                src.green(),
                "->".dimmed(),
                dst.yellow(),
                packet.payload.len()
            );
        }

        let payload_str = packet.payload_str();
        if !payload_str.is_empty() {
            if self.hex {
                print_hex(&packet.payload);
            } else {
                print_highlighted(&payload_str, pattern);
            }
        }
    }

    fn print_stream_text(&self, stream: &StreamData, pattern: &Option<Regex>) {
        if !self.quiet {
            eprintln!(
                "{} {} ({} bytes)",
                "STREAM".cyan().bold(),
                stream.key.to_string().green(),
                stream.payload.len()
            );
        }

        let payload_str = stream.payload_str();
        if !payload_str.is_empty() {
            if self.hex {
                print_hex(&stream.payload);
            } else {
                print_highlighted(&payload_str, pattern);
            }
        }
    }

    fn print_http_text(&self, stream_id: &str, msg: &HttpMessage, pattern: &Option<Regex>) {
        if !self.quiet {
            let label = match &msg.kind {
                crate::protocol::http::HttpKind::Request { method, uri, .. } => {
                    format!("{} {}", method, uri)
                }
                crate::protocol::http::HttpKind::Response { status, reason, .. } => {
                    format!("{} {}", status, reason)
                }
            };
            eprintln!(
                "{} {} {}",
                "HTTP".magenta().bold(),
                stream_id.green(),
                label.yellow()
            );
        }

        let display = msg.display_string();
        print_highlighted(&display, pattern);
    }

    fn print_packet_json(&self, packet: &ParsedPacket) {
        let j = json!({
            "type": "packet",
            "transport": format!("{:?}", packet.transport),
            "src_ip": packet.src_ip.map(|i| i.to_string()),
            "dst_ip": packet.dst_ip.map(|i| i.to_string()),
            "src_port": packet.src_port,
            "dst_port": packet.dst_port,
            "payload_len": packet.payload.len(),
            "payload": packet.payload_str(),
        });
        println!("{}", j);
    }

    fn print_stream_json(&self, stream: &StreamData) {
        let j = json!({
            "type": "stream",
            "stream": stream.key.to_string(),
            "payload_len": stream.payload.len(),
            "payload": stream.payload_str(),
        });
        println!("{}", j);
    }

    fn print_http_json(&self, stream_id: &str, msg: &HttpMessage) {
        let j = json!({
            "type": "http",
            "stream": stream_id,
            "message": msg,
        });
        println!("{}", j);
    }

    fn print_dns_text(&self, packet: &ParsedPacket, info: &DnsInfo, pattern: &Option<Regex>) {
        let src = format!(
            "{}:{}",
            packet.src_ip.map(|i| i.to_string()).unwrap_or_default(),
            packet.src_port.unwrap_or(0)
        );
        let dst = format!(
            "{}:{}",
            packet.dst_ip.map(|i| i.to_string()).unwrap_or_default(),
            packet.dst_port.unwrap_or(0)
        );

        if info.is_response {
            // Response line
            let qname = info
                .questions
                .first()
                .map(|q| q.name.as_str())
                .unwrap_or("?");
            let qtype = info
                .questions
                .first()
                .map(|q| q.qtype.as_str())
                .unwrap_or("?");
            let rcode = dns::rcode_str(info.rcode);

            if !self.quiet {
                eprintln!(
                    "{}  {} {} {}  {}  {}  {}",
                    "DNS R".magenta().bold(),
                    src.green(),
                    "→".dimmed(),
                    dst.yellow(),
                    qname.white().bold(),
                    qtype.cyan(),
                    rcode.yellow()
                );
            }

            // Print answer records
            for r in &info.answers {
                let line = format!("  {:<6}{:<40} TTL={}", r.rtype, r.rdata, r.ttl);
                print_highlighted(&line, pattern);
            }
            for r in &info.authorities {
                let line = format!("  {:<6}{:<40} TTL={} (auth)", r.rtype, r.rdata, r.ttl);
                print_highlighted(&line, pattern);
            }
        } else {
            // Query line
            let qname = info
                .questions
                .first()
                .map(|q| q.name.as_str())
                .unwrap_or("?");
            let qtype = info
                .questions
                .first()
                .map(|q| q.qtype.as_str())
                .unwrap_or("?");

            if !self.quiet {
                eprintln!(
                    "{}  {} {} {}  {}  {}",
                    "DNS Q".magenta().bold(),
                    src.green(),
                    "→".dimmed(),
                    dst.yellow(),
                    qname.white().bold(),
                    qtype.cyan()
                );
            }
        }
    }

    fn print_dns_json(&self, packet: &ParsedPacket, info: &DnsInfo) {
        let j = json!({
            "type": "dns",
            "src_ip": packet.src_ip.map(|i| i.to_string()),
            "dst_ip": packet.dst_ip.map(|i| i.to_string()),
            "src_port": packet.src_port,
            "dst_port": packet.dst_port,
            "dns": info,
        });
        println!("{}", j);
    }
}

/// Print payload with regex matches highlighted in red.
fn print_highlighted(text: &str, pattern: &Option<Regex>) {
    match pattern {
        Some(re) => {
            let mut last = 0;
            for m in re.find_iter(text) {
                print!("{}", &text[last..m.start()]);
                print!("{}", text[m.start()..m.end()].red().bold());
                last = m.end();
            }
            println!("{}", &text[last..]);
        }
        None => println!("{}", text),
    }
}

/// Print hex + ASCII dump.
fn print_hex(data: &[u8]) {
    for (i, chunk) in data.chunks(16).enumerate() {
        print!("{:08x}  ", i * 16);

        for (j, byte) in chunk.iter().enumerate() {
            print!("{:02x} ", byte);
            if j == 7 {
                print!(" ");
            }
        }

        let pad = 16 - chunk.len();
        for _ in 0..pad {
            print!("   ");
        }
        if chunk.len() <= 8 {
            print!(" ");
        }

        print!(" |");
        for byte in chunk {
            if byte.is_ascii_graphic() || *byte == b' ' {
                print!("{}", *byte as char);
            } else {
                print!(".");
            }
        }
        println!("|");
    }
}
