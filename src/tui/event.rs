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
