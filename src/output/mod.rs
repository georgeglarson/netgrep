use colored::Colorize;
use regex::bytes::Regex;
use serde_json::json;

use crate::protocol::ParsedPacket;
use crate::protocol::dns::{self, DnsInfo};
use crate::protocol::http::HttpMessage;
use crate::reassembly::StreamData;

/// Output formatter supporting text (with color highlighting), JSON, hex dump, and protocol-aware modes.
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
        let (_header, body) = self.format_packet_text(packet, pattern);
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
        if !body.is_empty() {
            if self.hex {
                let hex = format_hex(&packet.payload);
                print!("{}", hex);
            } else {
                print_highlighted_colored(&body, pattern);
            }
        }
    }

    fn print_stream_text(&self, stream: &StreamData, pattern: &Option<Regex>) {
        let (_header, body) = self.format_stream_text(stream, pattern);
        if !self.quiet {
            eprintln!(
                "{} {} ({} bytes)",
                "STREAM".cyan().bold(),
                stream.key.to_string().green(),
                stream.payload.len()
            );
        }
        if !body.is_empty() {
            if self.hex {
                let hex = format_hex(&stream.payload);
                print!("{}", hex);
            } else {
                print_highlighted_colored(&body, pattern);
            }
        }
    }

    pub fn print_http_text(&self, stream_id: &str, msg: &HttpMessage, pattern: &Option<Regex>) {
        let (_header, body) = self.format_http_text(stream_id, msg, pattern);
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
        print_highlighted_colored(&body, pattern);
    }

    fn print_packet_json(&self, packet: &ParsedPacket) {
        let j = self.format_packet_json(packet);
        println!("{}", j);
    }

    fn print_stream_json(&self, stream: &StreamData) {
        let j = self.format_stream_json(stream);
        println!("{}", j);
    }

    pub fn print_http_json(&self, stream_id: &str, msg: &HttpMessage) {
        let j = self.format_http_json(stream_id, msg);
        println!("{}", j);
    }

    fn print_dns_text(&self, packet: &ParsedPacket, info: &DnsInfo, pattern: &Option<Regex>) {
        let (_header, body) = self.format_dns_text(packet, info, pattern);
        if !self.quiet {
            let src = format_addr(packet.src_ip, packet.src_port);
            let dst = format_addr(packet.dst_ip, packet.dst_port);

            if info.is_response {
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
            } else {
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
        for line in body.lines() {
            print_highlighted_colored(line, pattern);
        }
    }

    fn print_dns_json(&self, packet: &ParsedPacket, info: &DnsInfo) {
        let j = self.format_dns_json(packet, info);
        println!("{}", j);
    }

    // -- Testable format methods --

    /// Format packet header and body text (no ANSI colors).
    pub fn format_packet_text(
        &self,
        packet: &ParsedPacket,
        pattern: &Option<Regex>,
    ) -> (String, String) {
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
        let header = format!(
            "{}{} {} -> {} ({} bytes){}",
            ts,
            proto,
            src,
            dst,
            packet.payload.len(),
            vlan_tag
        );

        let body = if self.hex {
            format_hex(&packet.payload)
        } else {
            let payload_str = packet.payload_str();
            format_highlighted(&payload_str, pattern)
        };

        (header, body)
    }

    /// Format stream header and body text (no ANSI colors).
    pub fn format_stream_text(
        &self,
        stream: &StreamData,
        pattern: &Option<Regex>,
    ) -> (String, String) {
        let header = format!("STREAM {} ({} bytes)", stream.key, stream.payload.len());
        let body = if self.hex {
            format_hex(&stream.payload)
        } else {
            let payload_str = stream.payload_str();
            format_highlighted(&payload_str, pattern)
        };
        (header, body)
    }

    /// Format HTTP message header and body text (no ANSI colors).
    pub fn format_http_text(
        &self,
        stream_id: &str,
        msg: &HttpMessage,
        pattern: &Option<Regex>,
    ) -> (String, String) {
        let label = match &msg.kind {
            crate::protocol::http::HttpKind::Request { method, uri, .. } => {
                format!("{} {}", method, uri)
            }
            crate::protocol::http::HttpKind::Response { status, reason, .. } => {
                format!("{} {}", status, reason)
            }
        };
        let header = format!("HTTP {} {}", stream_id, label);
        let display = msg.display_string();
        let body = format_highlighted(&display, pattern);
        (header, body)
    }

    /// Format DNS header and body text (no ANSI colors).
    pub fn format_dns_text(
        &self,
        packet: &ParsedPacket,
        info: &DnsInfo,
        _pattern: &Option<Regex>,
    ) -> (String, String) {
        let src = format_addr(packet.src_ip, packet.src_port);
        let dst = format_addr(packet.dst_ip, packet.dst_port);

        let header = if info.is_response {
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
            format!("DNS R  {} -> {}  {}  {}  {}", src, dst, qname, qtype, rcode)
        } else {
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
            format!("DNS Q  {} -> {}  {}  {}", src, dst, qname, qtype)
        };

        let mut body = String::new();
        if info.is_response {
            for r in &info.answers {
                let line = format!("  {:<6}{:<40} TTL={}\n", r.rtype, r.rdata, r.ttl);
                body.push_str(&line);
            }
            for r in &info.authorities {
                let line = format!("  {:<6}{:<40} TTL={} (auth)\n", r.rtype, r.rdata, r.ttl);
                body.push_str(&line);
            }
            for r in &info.additionals {
                let line = format!("  {:<6}{:<40} TTL={} (add)\n", r.rtype, r.rdata, r.ttl);
                body.push_str(&line);
            }
        }

        (header, body)
    }

    /// Format packet as JSON value.
    pub fn format_packet_json(&self, packet: &ParsedPacket) -> serde_json::Value {
        json!({
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
        })
    }

    /// Format stream as JSON value.
    pub fn format_stream_json(&self, stream: &StreamData) -> serde_json::Value {
        json!({
            "type": "stream",
            "stream": stream.key.to_string(),
            "payload_len": stream.payload.len(),
            "payload": stream.payload_str(),
        })
    }

    /// Format HTTP message as JSON value.
    pub fn format_http_json(&self, stream_id: &str, msg: &HttpMessage) -> serde_json::Value {
        json!({
            "type": "http",
            "stream": stream_id,
            "message": msg,
        })
    }

    /// Format DNS as JSON value.
    pub fn format_dns_json(&self, packet: &ParsedPacket, info: &DnsInfo) -> serde_json::Value {
        json!({
            "type": "dns",
            "src_ip": packet.src_ip.map(|i| i.to_string()),
            "dst_ip": packet.dst_ip.map(|i| i.to_string()),
            "src_port": packet.src_port,
            "dst_port": packet.dst_port,
            "dns": info,
        })
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

/// Build hex + ASCII dump as a String.
pub fn format_hex(data: &[u8]) -> String {
    use std::fmt::Write;
    let mut out = String::new();
    for (i, chunk) in data.chunks(16).enumerate() {
        write!(out, "{:08x}  ", i * 16).unwrap();

        for (j, byte) in chunk.iter().enumerate() {
            write!(out, "{:02x} ", byte).unwrap();
            if j == 7 {
                out.push(' ');
            }
        }

        let pad = 16 - chunk.len();
        for _ in 0..pad {
            out.push_str("   ");
        }
        if chunk.len() <= 8 {
            out.push(' ');
        }

        out.push_str(" |");
        for byte in chunk {
            if byte.is_ascii_graphic() || *byte == b' ' {
                out.push(*byte as char);
            } else {
                out.push('.');
            }
        }
        out.push_str("|\n");
    }
    out
}

/// Build highlighted text as a String (without ANSI colors).
/// Sanitizes control characters. Match regions are included as-is.
pub fn format_highlighted(text: &str, pattern: &Option<Regex>) -> String {
    let text = crate::sanitize::sanitize_control_chars(text);
    match pattern {
        Some(re) => {
            let bytes = text.as_bytes();
            let mut out = String::new();
            let mut last = 0;
            for m in re.find_iter(bytes) {
                if !text.is_char_boundary(m.start()) || !text.is_char_boundary(m.end()) {
                    continue;
                }
                out.push_str(&text[last..m.start()]);
                out.push_str(&text[m.start()..m.end()]);
                last = m.end();
            }
            out.push_str(&text[last..]);
            out
        }
        None => text,
    }
}

/// Print payload with regex matches highlighted in red (colored output to stdout).
fn print_highlighted_colored(text: &str, pattern: &Option<Regex>) {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{ParsedPacket, StreamKey, Transport};
    use crate::reassembly::{Direction, StreamData};
    use std::net::{IpAddr, Ipv4Addr};

    // T2: format_addr tests (L7)
    #[test]
    fn format_addr_with_port() {
        let ip = Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
        assert_eq!(format_addr(ip, Some(8080)), "10.0.0.1:8080");
    }

    #[test]
    fn format_addr_without_port() {
        let ip = Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
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

    // -- format_hex tests --

    #[test]
    fn format_hex_single_line() {
        let data = b"Hello";
        let hex = format_hex(data);
        assert!(hex.starts_with("00000000  "));
        assert!(hex.contains("48 65 6c 6c 6f"));
        assert!(hex.contains("|Hello|"));
    }

    #[test]
    fn format_hex_multiple_lines() {
        let data: Vec<u8> = (0..32).collect();
        let hex = format_hex(&data);
        assert!(hex.contains("00000000  "));
        assert!(hex.contains("00000010  "));
    }

    #[test]
    fn format_hex_non_printable() {
        let data = &[0x00, 0x01, 0x02];
        let hex = format_hex(data);
        assert!(hex.contains("|...|"));
    }

    #[test]
    fn format_hex_empty() {
        let hex = format_hex(&[]);
        assert_eq!(hex, "");
    }

    // -- format_highlighted tests --

    #[test]
    fn format_highlighted_no_pattern() {
        let result = format_highlighted("hello world", &None);
        assert_eq!(result, "hello world");
    }

    #[test]
    fn format_highlighted_with_match() {
        let re = Some(Regex::new("world").unwrap());
        let result = format_highlighted("hello world", &re);
        assert_eq!(result, "hello world");
    }

    #[test]
    fn format_highlighted_no_match() {
        let re = Some(Regex::new("xyz").unwrap());
        let result = format_highlighted("hello world", &re);
        assert_eq!(result, "hello world");
    }

    #[test]
    fn format_highlighted_multiple_matches() {
        let re = Some(Regex::new("o").unwrap());
        let result = format_highlighted("foo boo", &re);
        assert_eq!(result, "foo boo");
    }

    // -- Helper: make ParsedPacket --

    fn make_packet(src_port: Option<u16>, dst_port: Option<u16>, payload: &[u8]) -> ParsedPacket {
        ParsedPacket {
            src_ip: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
            dst_ip: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))),
            src_port,
            dst_port,
            transport: Transport::Tcp,
            payload: payload.to_vec(),
            tcp_flags: None,
            seq: None,
            vlan_id: None,
            icmp_type: None,
            icmp_code: None,
            timestamp: None,
        }
    }

    fn make_stream(payload: &[u8]) -> StreamData {
        StreamData {
            key: StreamKey::new(
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                1234,
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
                80,
            ),
            payload: payload.to_vec(),
            direction: Direction::Forward,
            src_addr: (IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 1234),
        }
    }

    // -- format_packet_text tests --

    #[test]
    fn format_packet_text_basic() {
        let f = Formatter::new(false, false, false, false, false);
        let pkt = make_packet(Some(1234), Some(80), b"hello");
        let (header, body) = f.format_packet_text(&pkt, &None);
        assert!(header.contains("Tcp"));
        assert!(header.contains("10.0.0.1:1234"));
        assert!(header.contains("10.0.0.2:80"));
        assert!(header.contains("5 bytes"));
        assert_eq!(body, "hello");
    }

    #[test]
    fn format_packet_text_quiet() {
        // Quiet flag doesn't change format_packet_text's header (it controls print behavior)
        // but verify it still generates correct body
        let f = Formatter::new(false, false, true, false, false);
        let pkt = make_packet(Some(1234), Some(80), b"data");
        let (_header, body) = f.format_packet_text(&pkt, &None);
        assert_eq!(body, "data");
    }

    #[test]
    fn format_packet_text_hex_mode() {
        let f = Formatter::new(false, true, false, false, false);
        let pkt = make_packet(Some(1234), Some(80), b"AB");
        let (_header, body) = f.format_packet_text(&pkt, &None);
        assert!(body.contains("00000000"));
        assert!(body.contains("41 42"));
        assert!(body.contains("|AB|"));
    }

    // -- format_stream_text tests --

    #[test]
    fn format_stream_text_basic() {
        let f = Formatter::new(false, false, false, false, false);
        let stream = make_stream(b"stream data");
        let (header, body) = f.format_stream_text(&stream, &None);
        assert!(header.contains("STREAM"));
        assert!(header.contains("11 bytes"));
        assert_eq!(body, "stream data");
    }

    // -- format_http_text tests --

    #[test]
    fn format_http_text_request() {
        let f = Formatter::new(false, false, false, true, false);
        let msg = crate::protocol::http::HttpMessage {
            kind: crate::protocol::http::HttpKind::Request {
                method: "GET".into(),
                uri: "/index.html".into(),
                version: "HTTP/1.1".into(),
            },
            headers: vec![("Host".into(), "example.com".into())],
            body: String::new(),
        };
        let (header, body) = f.format_http_text("stream-1", &msg, &None);
        assert!(header.contains("HTTP"));
        assert!(header.contains("GET /index.html"));
        assert!(body.contains("GET /index.html HTTP/1.1"));
        assert!(body.contains("Host: example.com"));
    }

    #[test]
    fn format_http_text_response() {
        let f = Formatter::new(false, false, false, true, false);
        let msg = crate::protocol::http::HttpMessage {
            kind: crate::protocol::http::HttpKind::Response {
                version: "HTTP/1.1".into(),
                status: 200,
                reason: "OK".into(),
            },
            headers: vec![],
            body: "hello".into(),
        };
        let (header, body) = f.format_http_text("stream-2", &msg, &None);
        assert!(header.contains("200 OK"));
        assert!(body.contains("HTTP/1.1 200 OK"));
    }

    // -- format_dns_text tests --

    #[test]
    fn format_dns_text_query() {
        let f = Formatter::new(false, false, false, false, true);
        let pkt = make_packet(Some(1234), Some(53), &[]);
        let info = DnsInfo {
            id: 0x1234,
            is_response: false,
            opcode: 0,
            rcode: 0,
            questions: vec![crate::protocol::dns::DnsQuestion {
                name: "example.com".into(),
                qtype: "A".into(),
            }],
            answers: vec![],
            authorities: vec![],
            additionals: vec![],
        };
        let (header, body) = f.format_dns_text(&pkt, &info, &None);
        assert!(header.contains("DNS Q"));
        assert!(header.contains("example.com"));
        assert!(header.contains("A"));
        assert!(body.is_empty()); // queries have no body records
    }

    #[test]
    fn format_dns_text_response() {
        let f = Formatter::new(false, false, false, false, true);
        let pkt = make_packet(Some(53), Some(1234), &[]);
        let info = DnsInfo {
            id: 0x1234,
            is_response: true,
            opcode: 0,
            rcode: 0,
            questions: vec![crate::protocol::dns::DnsQuestion {
                name: "example.com".into(),
                qtype: "A".into(),
            }],
            answers: vec![crate::protocol::dns::DnsRecord {
                name: "example.com".into(),
                rtype: "A".into(),
                ttl: 300,
                rdata: "93.184.216.34".into(),
            }],
            authorities: vec![],
            additionals: vec![],
        };
        let (header, body) = f.format_dns_text(&pkt, &info, &None);
        assert!(header.contains("DNS R"));
        assert!(header.contains("NOERROR"));
        assert!(body.contains("93.184.216.34"));
        assert!(body.contains("TTL=300"));
    }

    // -- JSON format tests --

    #[test]
    fn format_packet_json_keys() {
        let f = Formatter::new(true, false, false, false, false);
        let pkt = make_packet(Some(1234), Some(80), b"data");
        let j = f.format_packet_json(&pkt);
        assert_eq!(j["type"], "packet");
        assert_eq!(j["transport"], "Tcp");
        assert_eq!(j["payload_len"], 4);
        assert_eq!(j["payload"], "data");
        assert_eq!(j["src_port"], 1234);
        assert_eq!(j["dst_port"], 80);
    }

    #[test]
    fn format_stream_json_keys() {
        let f = Formatter::new(true, false, false, false, false);
        let stream = make_stream(b"payload");
        let j = f.format_stream_json(&stream);
        assert_eq!(j["type"], "stream");
        assert_eq!(j["payload_len"], 7);
        assert!(j["stream"].as_str().unwrap().contains("<->"));
    }

    #[test]
    fn format_http_json_keys() {
        let f = Formatter::new(true, false, false, true, false);
        let msg = crate::protocol::http::HttpMessage {
            kind: crate::protocol::http::HttpKind::Request {
                method: "POST".into(),
                uri: "/api".into(),
                version: "HTTP/1.1".into(),
            },
            headers: vec![],
            body: String::new(),
        };
        let j = f.format_http_json("stream-1", &msg);
        assert_eq!(j["type"], "http");
        assert_eq!(j["stream"], "stream-1");
        assert!(j["message"].is_object());
    }

    #[test]
    fn format_dns_json_keys() {
        let f = Formatter::new(true, false, false, false, true);
        let pkt = make_packet(Some(1234), Some(53), &[]);
        let info = DnsInfo {
            id: 0x1234,
            is_response: false,
            opcode: 0,
            rcode: 0,
            questions: vec![crate::protocol::dns::DnsQuestion {
                name: "test.org".into(),
                qtype: "AAAA".into(),
            }],
            answers: vec![],
            authorities: vec![],
            additionals: vec![],
        };
        let j = f.format_dns_json(&pkt, &info);
        assert_eq!(j["type"], "dns");
        assert!(j["dns"].is_object());
        assert_eq!(j["src_port"], 1234);
        assert_eq!(j["dst_port"], 53);
    }
}
