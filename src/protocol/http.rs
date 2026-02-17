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

/// Find the byte position of `\r\n\r\n` in a byte slice.
fn find_header_end(data: &[u8]) -> Option<usize> {
    data.windows(4).position(|w| w == b"\r\n\r\n")
}

/// Find the byte position of `\r\n` in a byte slice.
fn find_crlf(data: &[u8]) -> Option<usize> {
    data.windows(2).position(|w| w == b"\r\n")
}

/// Try to parse one or more HTTP messages from a stream payload.
/// Returns all successfully parsed messages.
/// Operates on raw bytes to avoid UTF-8 offset mismatches with binary bodies.
pub fn parse_http(data: &[u8]) -> Vec<HttpMessage> {
    let mut messages = Vec::new();
    let mut remaining = data;

    while !remaining.is_empty() {
        let header_end = match find_header_end(remaining) {
            Some(pos) => pos,
            None => break,
        };

        let header_section = &remaining[..header_end];
        let after_headers = &remaining[header_end + 4..];

        // Headers are text — parse as lossy UTF-8
        let header_text = String::from_utf8_lossy(header_section);
        let mut lines = header_text.lines();

        let start_line = match lines.next() {
            Some(l) => l,
            None => break,
        };

        let kind = if start_line.starts_with("HTTP/") {
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

        let mut headers = Vec::new();
        for line in lines {
            if let Some((key, value)) = line.split_once(':') {
                headers.push((key.trim().to_string(), value.trim().to_string()));
            }
        }

        let content_length: Option<usize> = headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("content-length"))
            .and_then(|(_, v)| v.parse().ok());

        let is_chunked = headers
            .iter()
            .any(|(k, v)| k.eq_ignore_ascii_case("transfer-encoding") && v.contains("chunked"));

        let (body, consumed) = if is_chunked {
            match decode_chunked(after_headers) {
                Some((decoded, bytes_consumed)) => (
                    String::from_utf8_lossy(&decoded).into_owned(),
                    bytes_consumed,
                ),
                None => (String::new(), 0),
            }
        } else {
            let len = content_length.unwrap_or(0).min(after_headers.len());
            (
                String::from_utf8_lossy(&after_headers[..len]).into_owned(),
                len,
            )
        };

        remaining = &after_headers[consumed..];

        messages.push(HttpMessage {
            kind,
            headers,
            body,
        });
    }

    messages
}

/// Decode a chunked transfer-encoded body from raw bytes.
/// Returns (decoded_body_bytes, total_bytes_consumed) or None if incomplete.
fn decode_chunked(data: &[u8]) -> Option<(Vec<u8>, usize)> {
    let mut decoded = Vec::new();
    let mut pos = 0;

    loop {
        let line_end = find_crlf(&data[pos..])?;
        let size_line = &data[pos..pos + line_end];

        // Chunk size line is ASCII — parse as string
        let size_str = std::str::from_utf8(size_line).ok()?;
        let size_part = size_str.split(';').next().unwrap_or(size_str).trim();
        let chunk_size = usize::from_str_radix(size_part, 16).ok()?;

        pos += line_end + 2;

        if chunk_size == 0 {
            if let Some(trailer_end) = find_crlf(&data[pos..]) {
                pos += trailer_end + 2;
            }
            break;
        }

        if pos + chunk_size > data.len() {
            return None;
        }

        decoded.extend_from_slice(&data[pos..pos + chunk_size]);
        pos += chunk_size;

        if data[pos..].starts_with(b"\r\n") {
            pos += 2;
        } else {
            return None;
        }
    }

    Some((decoded, pos))
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- decode_chunked tests --

    #[test]
    fn chunked_single_chunk() {
        let data = b"5\r\nhello\r\n0\r\n\r\n";
        let (body, consumed) = decode_chunked(data).unwrap();
        assert_eq!(body, b"hello");
        assert_eq!(consumed, data.len());
    }

    #[test]
    fn chunked_multiple_chunks() {
        let data = b"5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n";
        let (body, _) = decode_chunked(data).unwrap();
        assert_eq!(body, b"hello world");
    }

    #[test]
    fn chunked_with_extension() {
        let data = b"5;name=value\r\nhello\r\n0\r\n\r\n";
        let (body, _) = decode_chunked(data).unwrap();
        assert_eq!(body, b"hello");
    }

    #[test]
    fn chunked_incomplete_body() {
        // Says 10 bytes but only 5 available
        let data = b"a\r\nhello\r\n";
        assert!(decode_chunked(data.as_slice()).is_none());
    }

    #[test]
    fn chunked_missing_crlf_after_data() {
        let data = b"5\r\nhello0\r\n\r\n"; // missing \r\n after "hello"
        assert!(decode_chunked(data.as_slice()).is_none());
    }

    #[test]
    fn chunked_invalid_hex() {
        let data = b"xyz\r\nhello\r\n0\r\n\r\n";
        assert!(decode_chunked(data.as_slice()).is_none());
    }

    #[test]
    fn chunked_no_terminating_crlf() {
        // Incomplete — no \r\n after chunk size
        let data = b"5";
        assert!(decode_chunked(data.as_slice()).is_none());
    }

    #[test]
    fn chunked_empty_body() {
        let data = b"0\r\n\r\n";
        let (body, _) = decode_chunked(data).unwrap();
        assert_eq!(body, b"");
    }

    // -- parse_http tests --

    #[test]
    fn parse_simple_request() {
        let data = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let msgs = parse_http(data);
        assert_eq!(msgs.len(), 1);
        match &msgs[0].kind {
            HttpKind::Request {
                method,
                uri,
                version,
            } => {
                assert_eq!(method, "GET");
                assert_eq!(uri, "/index.html");
                assert_eq!(version, "HTTP/1.1");
            }
            _ => panic!("Expected request"),
        }
        assert_eq!(msgs[0].headers.len(), 1);
        assert_eq!(msgs[0].headers[0].0, "Host");
        assert_eq!(msgs[0].headers[0].1, "example.com");
    }

    #[test]
    fn parse_response_with_body() {
        let data = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";
        let msgs = parse_http(data);
        assert_eq!(msgs.len(), 1);
        match &msgs[0].kind {
            HttpKind::Response { status, reason, .. } => {
                assert_eq!(*status, 200);
                assert_eq!(reason, "OK");
            }
            _ => panic!("Expected response"),
        }
        assert_eq!(msgs[0].body, "hello");
    }

    #[test]
    fn parse_response_missing_reason() {
        let data = b"HTTP/1.1 204\r\n\r\n";
        let msgs = parse_http(data);
        assert_eq!(msgs.len(), 1);
        match &msgs[0].kind {
            HttpKind::Response { status, .. } => {
                assert_eq!(*status, 204);
            }
            _ => panic!("Expected response"),
        }
    }

    #[test]
    fn parse_multiple_messages() {
        let data =
            b"GET / HTTP/1.1\r\nHost: a\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi";
        let msgs = parse_http(data);
        assert_eq!(msgs.len(), 2);
        assert!(matches!(&msgs[0].kind, HttpKind::Request { .. }));
        assert!(matches!(&msgs[1].kind, HttpKind::Response { .. }));
        assert_eq!(msgs[1].body, "hi");
    }

    #[test]
    fn parse_chunked_response() {
        let data = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n";
        let msgs = parse_http(data);
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].body, "hello");
    }

    #[test]
    fn parse_no_body_no_content_length() {
        let data = b"GET / HTTP/1.1\r\n\r\n";
        let msgs = parse_http(data);
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].body, "");
    }

    #[test]
    fn parse_content_length_case_insensitive() {
        let data = b"HTTP/1.1 200 OK\r\ncontent-length: 3\r\n\r\nabc";
        let msgs = parse_http(data);
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].body, "abc");
    }

    #[test]
    fn parse_no_header_terminator() {
        let data = b"GET / HTTP/1.1\r\nHost: x";
        let msgs = parse_http(data);
        assert!(msgs.is_empty());
    }

    #[test]
    fn parse_request_missing_version() {
        let data = b"GET /\r\n\r\n";
        let msgs = parse_http(data);
        assert_eq!(msgs.len(), 1);
        match &msgs[0].kind {
            HttpKind::Request { version, .. } => {
                assert_eq!(version, "HTTP/1.1"); // default
            }
            _ => panic!("Expected request"),
        }
    }

    #[test]
    fn parse_empty_input() {
        let msgs = parse_http(b"");
        assert!(msgs.is_empty());
    }
}
