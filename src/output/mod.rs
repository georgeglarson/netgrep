use colored::Colorize;
use regex::bytes::Regex;
use serde_json::json;

use crate::protocol::ParsedPacket;
use crate::protocol::dns::{self, DnsInfo};
use crate::protocol::http::HttpMessage;
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
        if self.dns && packet.is_dns_port() {
            let dns_data = dns::strip_tcp_prefix(&packet.payload, packet.is_tcp());
            if let Some(info) = dns::parse_dns(dns_data) {
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
            let ts = packet
                .timestamp
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| {
                    let secs = d.as_secs();
                    let usecs = d.subsec_micros();
                    format!("{}.{:06} ", secs, usecs)
                })
                .unwrap_or_default();
            let proto = match (packet.icmp_type, packet.icmp_code) {
                (Some(t), Some(c)) => format!("{:?} type={} code={}", packet.transport, t, c),
                _ => format!("{:?}", packet.transport),
            };
            let src = format_addr(packet.src_ip, packet.src_port);
            let dst = format_addr(packet.dst_ip, packet.dst_port);
            let vlan_tag = match packet.vlan_id {
                Some(id) => format!(" vlan={}", id),
                None => String::new(),
            };
            eprintln!(
                "{}{} {} {} {} ({} bytes){}",
                ts.dimmed(),
                proto.blue(),
                src.green(),
                "->".dimmed(),
                dst.yellow(),
                packet.payload.len(),
                vlan_tag
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

    pub fn print_http_text(&self, stream_id: &str, msg: &HttpMessage, pattern: &Option<Regex>) {
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
            "vlan_id": packet.vlan_id,
            "icmp_type": packet.icmp_type,
            "icmp_code": packet.icmp_code,
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

    pub fn print_http_json(&self, stream_id: &str, msg: &HttpMessage) {
        let j = json!({
            "type": "http",
            "stream": stream_id,
            "message": msg,
        });
        println!("{}", j);
    }

    fn print_dns_text(&self, packet: &ParsedPacket, info: &DnsInfo, pattern: &Option<Regex>) {
        let src = format_addr(packet.src_ip, packet.src_port);
        let dst = format_addr(packet.dst_ip, packet.dst_port);

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
            for r in &info.additionals {
                let line = format!("  {:<6}{:<40} TTL={} (add)", r.rtype, r.rdata, r.ttl);
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

// L7: Show IP only (no `:0`) when port is None.
fn format_addr(ip: Option<std::net::IpAddr>, port: Option<u16>) -> String {
    let ip_str = ip.map(|i| i.to_string()).unwrap_or_default();
    match port {
        Some(p) => format!("{}:{}", ip_str, p),
        None => ip_str,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // T2: format_addr tests (L7)
    #[test]
    fn format_addr_with_port() {
        let ip = Some(std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1)));
        assert_eq!(format_addr(ip, Some(8080)), "10.0.0.1:8080");
    }

    #[test]
    fn format_addr_without_port() {
        let ip = Some(std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1)));
        assert_eq!(format_addr(ip, None), "10.0.0.1");
    }

    #[test]
    fn format_addr_no_ip_no_port() {
        assert_eq!(format_addr(None, None), "");
    }

    #[test]
    fn format_addr_no_ip_with_port() {
        assert_eq!(format_addr(None, Some(80)), ":80");
    }
}

/// Print payload with regex matches highlighted in red.
fn print_highlighted(text: &str, pattern: &Option<Regex>) {
    let text = &crate::sanitize::sanitize_control_chars(text);
    match pattern {
        Some(re) => {
            let bytes = text.as_bytes();
            let mut last = 0;
            for m in re.find_iter(bytes) {
                // Skip matches that land on non-UTF-8 boundaries (from lossy conversion)
                if !text.is_char_boundary(m.start()) || !text.is_char_boundary(m.end()) {
                    continue;
                }
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
