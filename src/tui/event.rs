use std::borrow::Cow;

use crate::protocol::ParsedPacket;
use crate::protocol::dns::{self, DnsInfo};
use crate::protocol::http::{self, HttpMessage};
use crate::reassembly::StreamData;

/// A single capture event displayed in the TUI, containing a summary row and detail pane content.
pub struct CaptureEvent {
    pub id: usize,
    pub summary: RowSummary,
    pub detail: DetailContent,
}

/// Summary columns for one row in the TUI packet table.
pub struct RowSummary {
    pub proto: String,
    pub src: String,
    pub dst: String,
    pub info: String,
}

/// Content shown in the TUI detail pane when a row is selected.
pub enum DetailContent {
    Packet { header: String, payload: Vec<u8> },
    Stream { header: String, payload: Vec<u8> },
    Http { header: String, display: String },
    Dns { header: String, display: String },
}

impl DetailContent {
    pub fn header(&self) -> &str {
        match self {
            DetailContent::Packet { header, .. } => header,
            DetailContent::Stream { header, .. } => header,
            DetailContent::Http { header, .. } => header,
            DetailContent::Dns { header, .. } => header,
        }
    }

    /// Approximate heap size of the detail content in bytes.
    pub fn approx_bytes(&self) -> usize {
        match self {
            DetailContent::Packet { header, payload } => header.len() + payload.len(),
            DetailContent::Stream { header, payload } => header.len() + payload.len(),
            DetailContent::Http { header, display } => header.len() + display.len(),
            DetailContent::Dns { header, display } => header.len() + display.len(),
        }
    }

    // L5: Return Cow<str> to avoid allocation when the content is already a String.
    pub fn body_text(&self) -> Cow<'_, str> {
        match self {
            DetailContent::Packet { payload, .. } => String::from_utf8_lossy(payload),
            DetailContent::Stream { payload, .. } => String::from_utf8_lossy(payload),
            DetailContent::Http { display, .. } => Cow::Borrowed(display),
            DetailContent::Dns { display, .. } => Cow::Borrowed(display),
        }
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

impl CaptureEvent {
    pub fn from_packet(id: usize, parsed: &ParsedPacket, dns_mode: bool) -> Self {
        let src = format_addr(parsed.src_ip, parsed.src_port);
        let dst = format_addr(parsed.dst_ip, parsed.dst_port);

        // Check for DNS (strip 2-byte TCP length prefix if needed)
        if dns_mode && parsed.is_dns_port() {
            let dns_data = dns::strip_tcp_prefix(&parsed.payload, parsed.is_tcp());
            if let Some(info) = dns::parse_dns(dns_data) {
                return Self::from_dns(id, &src, &dst, &info);
            }
        }

        let proto = format!("{:?}", parsed.transport);
        let info = if parsed.payload.is_empty() {
            String::new()
        } else {
            let s = crate::sanitize::sanitize_control_chars(&parsed.payload_str());
            // First line or truncated preview
            s.lines().next().unwrap_or("").chars().take(80).collect()
        };

        let header = format!(
            "{} {} -> {} ({} bytes)",
            proto,
            src,
            dst,
            parsed.payload.len()
        );

        CaptureEvent {
            id,
            summary: RowSummary {
                proto,
                src,
                dst,
                info,
            },
            detail: DetailContent::Packet {
                header,
                payload: parsed.payload.clone(),
            },
        }
    }

    pub fn from_stream(id: usize, stream: &StreamData, http_mode: bool) -> Self {
        let src = format!("{}:{}", stream.key.addr_a, stream.key.port_a);
        let dst = format!("{}:{}", stream.key.addr_b, stream.key.port_b);

        if http_mode {
            let messages = http::parse_http(&stream.payload);
            if !messages.is_empty() {
                return Self::from_http_messages(
                    id,
                    &src,
                    &dst,
                    &stream.key.to_string(),
                    &messages,
                );
            }
        }

        let payload_str = crate::sanitize::sanitize_control_chars(&stream.payload_str());
        let info = payload_str
            .lines()
            .next()
            .unwrap_or("")
            .chars()
            .take(80)
            .collect();

        let header = format!("STREAM {} ({} bytes)", stream.key, stream.payload.len());

        CaptureEvent {
            id,
            summary: RowSummary {
                proto: "TCP".into(),
                src,
                dst,
                info,
            },
            detail: DetailContent::Stream {
                header,
                payload: stream.payload.clone(),
            },
        }
    }

    fn from_dns(id: usize, src: &str, dst: &str, info: &DnsInfo) -> Self {
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

        let (proto, short_info) = if info.is_response {
            let rcode = dns::rcode_str(info.rcode);
            ("DNS R".into(), format!("{} {} {}", qname, qtype, rcode))
        } else {
            ("DNS Q".into(), format!("{} {}", qname, qtype))
        };

        let mut display = String::new();
        for q in &info.questions {
            display.push_str(&format!("Q: {} {}\n", q.name, q.qtype));
        }
        for r in &info.answers {
            display.push_str(&format!(
                "A: {} {} {} TTL={}\n",
                r.name, r.rtype, r.rdata, r.ttl
            ));
        }
        for r in &info.authorities {
            display.push_str(&format!(
                "AUTH: {} {} {} TTL={}\n",
                r.name, r.rtype, r.rdata, r.ttl
            ));
        }
        for r in &info.additionals {
            display.push_str(&format!(
                "ADD: {} {} {} TTL={}\n",
                r.name, r.rtype, r.rdata, r.ttl
            ));
        }

        let header = if info.is_response {
            format!("DNS Response {} -> {}", src, dst)
        } else {
            format!("DNS Query {} -> {}", src, dst)
        };

        CaptureEvent {
            id,
            summary: RowSummary {
                proto,
                src: src.to_string(),
                dst: dst.to_string(),
                info: short_info,
            },
            detail: DetailContent::Dns { header, display },
        }
    }

    pub fn from_h2_messages(
        id: usize,
        stream_key: &crate::protocol::StreamKey,
        messages: &[HttpMessage],
    ) -> Self {
        let src = format!("{}:{}", stream_key.addr_a, stream_key.port_a);
        let dst = format!("{}:{}", stream_key.addr_b, stream_key.port_b);
        Self::from_http_messages(id, &src, &dst, &stream_key.to_string(), messages)
    }

    fn from_http_messages(
        id: usize,
        src: &str,
        dst: &str,
        stream_id: &str,
        messages: &[HttpMessage],
    ) -> Self {
        // L6: Guard for empty messages slice
        let first = match messages.first() {
            Some(f) => f,
            None => {
                return CaptureEvent {
                    id,
                    summary: RowSummary {
                        proto: "HTTP".into(),
                        src: src.to_string(),
                        dst: dst.to_string(),
                        info: String::new(),
                    },
                    detail: DetailContent::Http {
                        header: format!("HTTP {} (empty)", stream_id),
                        display: String::new(),
                    },
                };
            }
        };
        let info = match &first.kind {
            crate::protocol::http::HttpKind::Request { method, uri, .. } => {
                format!("{} {}", method, uri)
            }
            crate::protocol::http::HttpKind::Response { status, reason, .. } => {
                format!("{} {}", status, reason)
            }
        };

        let count_suffix = if messages.len() > 1 {
            format!(" (+{} more)", messages.len() - 1)
        } else {
            String::new()
        };

        let header = format!("HTTP {} {}{}", stream_id, &info, count_suffix);

        // Combine all messages into the display
        let display: String = messages
            .iter()
            .map(|msg| msg.display_string())
            .collect::<Vec<_>>()
            .join("\n---\n");

        CaptureEvent {
            id,
            summary: RowSummary {
                proto: "HTTP".into(),
                src: src.to_string(),
                dst: dst.to_string(),
                info,
            },
            detail: DetailContent::Http { header, display },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::http::{HttpKind, HttpMessage};
    use crate::protocol::{ParsedPacket, StreamKey, Transport};
    use crate::reassembly::{Direction, StreamData};
    use std::net::{IpAddr, Ipv4Addr};

    fn make_packet(
        src_port: Option<u16>,
        dst_port: Option<u16>,
        transport: Transport,
        payload: &[u8],
    ) -> ParsedPacket {
        ParsedPacket {
            src_ip: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
            dst_ip: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))),
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

    fn make_stream_key() -> StreamKey {
        StreamKey::new(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            1234,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            443,
        )
    }

    // -- DetailContent tests --

    #[test]
    fn detail_content_packet_header() {
        let dc = DetailContent::Packet {
            header: "test header".into(),
            payload: b"data".to_vec(),
        };
        assert_eq!(dc.header(), "test header");
    }

    #[test]
    fn detail_content_stream_approx_bytes() {
        let dc = DetailContent::Stream {
            header: "hdr".into(),
            payload: vec![0u8; 100],
        };
        assert_eq!(dc.approx_bytes(), 3 + 100);
    }

    #[test]
    fn detail_content_http_body_text() {
        let dc = DetailContent::Http {
            header: "h".into(),
            display: "GET / HTTP/1.1".into(),
        };
        assert_eq!(dc.body_text().as_ref(), "GET / HTTP/1.1");
    }

    #[test]
    fn detail_content_dns_body_text() {
        let dc = DetailContent::Dns {
            header: "dns".into(),
            display: "Q: example.com A".into(),
        };
        assert_eq!(dc.body_text().as_ref(), "Q: example.com A");
    }

    #[test]
    fn detail_content_packet_body_text_lossy() {
        let dc = DetailContent::Packet {
            header: "h".into(),
            payload: vec![0xFF, 0xFE, b'a', b'b'],
        };
        let text = dc.body_text();
        assert!(text.contains("ab"));
    }

    #[test]
    fn detail_content_stream_header() {
        let dc = DetailContent::Stream {
            header: "STREAM 10.0.0.1:1234 <-> 10.0.0.2:80".into(),
            payload: vec![],
        };
        assert_eq!(dc.header(), "STREAM 10.0.0.1:1234 <-> 10.0.0.2:80");
    }

    // -- format_addr tests --

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

    // -- from_packet tests --

    #[test]
    fn from_packet_tcp_basic() {
        let pkt = make_packet(Some(1234), Some(80), Transport::Tcp, b"hello");
        let event = CaptureEvent::from_packet(1, &pkt, false);
        assert_eq!(event.id, 1);
        assert_eq!(event.summary.proto, "Tcp");
        assert!(event.summary.src.contains("10.0.0.1:1234"));
        assert!(event.summary.dst.contains("10.0.0.2:80"));
        assert_eq!(event.summary.info, "hello");
        assert!(event.detail.header().contains("Tcp"));
    }

    #[test]
    fn from_packet_udp_basic() {
        let pkt = make_packet(Some(5000), Some(53), Transport::Udp, b"query");
        let event = CaptureEvent::from_packet(2, &pkt, false);
        assert_eq!(event.summary.proto, "Udp");
    }

    #[test]
    fn from_packet_empty_payload() {
        let pkt = make_packet(Some(1234), Some(80), Transport::Tcp, &[]);
        let event = CaptureEvent::from_packet(3, &pkt, false);
        assert_eq!(event.summary.info, "");
        assert!(event.detail.header().contains("0 bytes"));
    }

    #[test]
    fn from_packet_dns_mode_on_port_53() {
        // Build a valid DNS query
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
        let event = CaptureEvent::from_packet(4, &parsed, true);
        assert_eq!(event.summary.proto, "DNS Q");
        assert!(event.summary.info.contains("example.com"));
    }

    #[test]
    fn from_packet_dns_mode_non_dns_port() {
        let pkt = make_packet(Some(8080), Some(80), Transport::Tcp, b"not dns");
        let event = CaptureEvent::from_packet(5, &pkt, true);
        // Should not be DNS, falls through to regular packet
        assert_eq!(event.summary.proto, "Tcp");
    }

    // -- from_stream tests --

    #[test]
    fn from_stream_basic() {
        let stream = make_stream(b"stream payload");
        let event = CaptureEvent::from_stream(1, &stream, false);
        assert_eq!(event.summary.proto, "TCP");
        assert!(event.detail.header().contains("STREAM"));
        assert!(event.detail.header().contains("14 bytes"));
    }

    #[test]
    fn from_stream_http_mode_with_http_payload() {
        let http_payload = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let stream = make_stream(http_payload);
        let event = CaptureEvent::from_stream(2, &stream, true);
        assert_eq!(event.summary.proto, "HTTP");
        assert!(event.summary.info.contains("GET /"));
    }

    #[test]
    fn from_stream_http_mode_non_http_payload() {
        let stream = make_stream(b"not http content");
        let event = CaptureEvent::from_stream(3, &stream, true);
        // Doesn't parse as HTTP, falls through to plain stream
        assert_eq!(event.summary.proto, "TCP");
    }

    // -- from_h2_messages tests --

    #[test]
    fn from_h2_messages_single() {
        let key = make_stream_key();
        let msg = HttpMessage {
            kind: HttpKind::Request {
                method: "GET".into(),
                uri: "/api".into(),
                version: "HTTP/2".into(),
            },
            headers: vec![],
            body: String::new(),
        };
        let event = CaptureEvent::from_h2_messages(1, &key, &[msg]);
        assert_eq!(event.summary.proto, "HTTP");
        assert!(event.summary.info.contains("GET /api"));
    }

    #[test]
    fn from_h2_messages_multiple() {
        let key = make_stream_key();
        let msg1 = HttpMessage {
            kind: HttpKind::Request {
                method: "GET".into(),
                uri: "/a".into(),
                version: "HTTP/2".into(),
            },
            headers: vec![],
            body: String::new(),
        };
        let msg2 = HttpMessage {
            kind: HttpKind::Response {
                version: "HTTP/2".into(),
                status: 200,
                reason: "OK".into(),
            },
            headers: vec![],
            body: String::new(),
        };
        let event = CaptureEvent::from_h2_messages(2, &key, &[msg1, msg2]);
        assert!(event.detail.header().contains("+1 more"));
        let body = event.detail.body_text();
        assert!(body.contains("---")); // separator between messages
    }
}
