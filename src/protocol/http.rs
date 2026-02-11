use serde::Serialize;

/// Parsed HTTP message (request or response).
#[derive(Debug, Serialize)]
pub struct HttpMessage {
    pub kind: HttpKind,
    pub headers: Vec<(String, String)>,
    pub body: String,
}

#[derive(Debug, Serialize)]
pub enum HttpKind {
    Request {
        method: String,
        uri: String,
        version: String,
    },
    Response {
        version: String,
        status: u16,
        reason: String,
    },
}

impl HttpMessage {
    pub fn header(&self, name: &str) -> Option<&str> {
        let name_lower = name.to_ascii_lowercase();
        self.headers
            .iter()
            .find(|(k, _)| k.to_ascii_lowercase() == name_lower)
            .map(|(_, v)| v.as_str())
    }

    /// Format for display: status line + headers + body.
    pub fn display_string(&self) -> String {
        let mut out = String::new();

        match &self.kind {
            HttpKind::Request {
                method,
                uri,
                version,
            } => {
                out.push_str(&format!("{} {} {}\r\n", method, uri, version));
            }
            HttpKind::Response {
                version,
                status,
                reason,
            } => {
                out.push_str(&format!("{} {} {}\r\n", version, status, reason));
            }
        }

        for (k, v) in &self.headers {
            out.push_str(&format!("{}: {}\r\n", k, v));
        }

        out.push_str("\r\n");

        if !self.body.is_empty() {
            out.push_str(&self.body);
        }

        out
    }
}

/// Try to parse one or more HTTP messages from a stream payload.
/// Returns all successfully parsed messages.
pub fn parse_http(data: &[u8]) -> Vec<HttpMessage> {
    let text = String::from_utf8_lossy(data);
    let mut messages = Vec::new();
    let mut remaining = text.as_ref();

    while !remaining.is_empty() {
        // Find the end of headers
        let header_end = match remaining.find("\r\n\r\n") {
            Some(pos) => pos,
            None => break,
        };

        let header_section = &remaining[..header_end];
        let after_headers = &remaining[header_end + 4..];

        let mut lines = header_section.lines();

        // Parse the start line
        let start_line = match lines.next() {
            Some(l) => l,
            None => break,
        };

        let kind = if start_line.starts_with("HTTP/") {
            // Response
            let parts: Vec<&str> = start_line.splitn(3, ' ').collect();
            if parts.len() < 2 {
                break;
            }
            HttpKind::Response {
                version: parts[0].to_string(),
                status: parts[1].parse().unwrap_or(0),
                reason: parts.get(2).unwrap_or(&"").to_string(),
            }
        } else {
            // Request
            let parts: Vec<&str> = start_line.splitn(3, ' ').collect();
            if parts.len() < 2 {
                break;
            }
            HttpKind::Request {
                method: parts[0].to_string(),
                uri: parts[1].to_string(),
                version: parts.get(2).unwrap_or(&"HTTP/1.1").to_string(),
            }
        };

        // Parse headers
        let mut headers = Vec::new();
        for line in lines {
            if let Some((key, value)) = line.split_once(':') {
                headers.push((key.trim().to_string(), value.trim().to_string()));
            }
        }

        // Extract body based on Content-Length if present
        let content_length: usize = headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("content-length"))
            .and_then(|(_, v)| v.parse().ok())
            .unwrap_or(0);

        let body_len = content_length.min(after_headers.len());
        let body = after_headers[..body_len].to_string();

        remaining = &after_headers[body_len..];

        messages.push(HttpMessage {
            kind,
            headers,
            body,
        });
    }

    messages
}
