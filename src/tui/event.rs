use crate::protocol::dns::{self, DnsInfo};
use crate::protocol::http::{self, HttpMessage};
use crate::protocol::{ParsedPacket, Transport};
use crate::reassembly::StreamData;

pub struct CaptureEvent {
    pub id: usize,
    pub summary: RowSummary,
    pub detail: DetailContent,
}

pub struct RowSummary {
    pub proto: String,
    pub src: String,
    pub dst: String,
    pub info: String,
}

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

    pub fn body_text(&self) -> String {
        match self {
            DetailContent::Packet { payload, .. } => String::from_utf8_lossy(payload).into_owned(),
            DetailContent::Stream { payload, .. } => String::from_utf8_lossy(payload).into_owned(),
            DetailContent::Http { display, .. } => display.clone(),
            DetailContent::Dns { display, .. } => display.clone(),
        }
    }
}

fn format_addr(ip: Option<std::net::IpAddr>, port: Option<u16>) -> String {
    format!(
        "{}:{}",
        ip.map(|i| i.to_string()).unwrap_or_default(),
        port.unwrap_or(0)
    )
}

impl CaptureEvent {
    pub fn from_packet(id: usize, parsed: &ParsedPacket, dns_mode: bool) -> Self {
        let src = format_addr(parsed.src_ip, parsed.src_port);
        let dst = format_addr(parsed.dst_ip, parsed.dst_port);

        // Check for DNS
        if dns_mode && parsed.transport == Transport::Udp && parsed.is_dns_port() {
            if let Some(info) = dns::parse_dns(&parsed.payload) {
                return Self::from_dns(id, &src, &dst, &info);
            }
        }

        let proto = format!("{:?}", parsed.transport);
        let info = if parsed.payload.is_empty() {
            String::new()
        } else {
            let s = parsed.payload_str();
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

        let payload_str = stream.payload_str();
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

    fn from_http_messages(
        id: usize,
        src: &str,
        dst: &str,
        stream_id: &str,
        messages: &[HttpMessage],
    ) -> Self {
        // Summary shows the first message's info
        let first = &messages[0];
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
