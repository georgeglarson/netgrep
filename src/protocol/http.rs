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
    /// L8: Uses write! to avoid intermediate format! allocations.
    pub fn display_string(&self) -> String {
        use std::fmt::Write;
        let mut out = String::new();

        match &self.kind {
            HttpKind::Request {
                method,
                uri,
                version,
            } => {
                let _ = write!(out, "{} {} {}\r\n", method, uri, version);
            }
            HttpKind::Response {
                version,
                status,
                reason,
            } => {
                let _ = write!(out, "{} {} {}\r\n", version, status, reason);
            }
        }

        for (k, v) in &self.headers {
            let _ = write!(out, "{}: {}\r\n", k, v);
        }

        out.push_str("\r\n");

        if !self.body.is_empty() {
            out.push_str(&self.body);
        }

        out
    }
}

/// L18: Find the byte position of the header terminator.
/// Prefers `\r\n\r\n` but falls back to `\n\n`.
/// Returns (position, separator_length).
fn find_header_end(data: &[u8]) -> Option<(usize, usize)> {
    if let Some(pos) = data.windows(4).position(|w| w == b"\r\n\r\n") {
        return Some((pos, 4));
    }
    if let Some(pos) = data.windows(2).position(|w| w == b"\n\n") {
        return Some((pos, 2));
    }
    None
}

/// Find the byte position of `\r\n` in a byte slice.
fn find_crlf(data: &[u8]) -> Option<usize> {
    data.windows(2).position(|w| w == b"\r\n")
}

/// Known HTTP methods for M10 request validation.
const KNOWN_METHODS: &[&str] = &[
    "GET", "HEAD", "POST", "PUT", "DELETE", "CONNECT", "OPTIONS", "TRACE", "PATCH",
];

/// M11: Maximum chunked body size (10 MB).
const MAX_CHUNKED_BODY: usize = 10 * 1024 * 1024;

/// H1: Find the start of the next HTTP message in a byte slice.
/// Looks for request methods and "HTTP/" response starts.
/// M7: Uses first-byte filtering to avoid O(n*m) scanning.
/// M6: Requires full "HTTP/x.y NNN" pattern for response starts to reduce
/// false splits in close-delimited response bodies.
fn find_next_http_start(data: &[u8]) -> Option<usize> {
    for i in 0..data.len() {
        // M7: Filter by first byte before attempting starts_with comparisons
        match data[i] {
            b'H' => {
                // M6: Require "HTTP/" followed by digit.digit space digit
                // to avoid false-matching "HTTP/" in body content.
                if data.len() >= i + 10
                    && data[i..].starts_with(b"HTTP/")
                    && data[i + 5].is_ascii_digit()
                    && data[i + 6] == b'.'
                    && data[i + 7].is_ascii_digit()
                    && data[i + 8] == b' '
                    && data[i + 9].is_ascii_digit()
                {
                    return Some(i);
                }
            }
            b'G' | b'P' | b'D' | b'C' | b'O' | b'T' => {
                for method in KNOWN_METHODS {
                    if data[i..].starts_with(method.as_bytes()) {
                        let after = i + method.len();
                        if after < data.len() && data[after] == b' ' {
                            return Some(i);
                        }
                    }
                }
            }
            _ => {}
        }
    }
    None
}

/// Try to parse one or more HTTP messages from a stream payload.
/// Returns all successfully parsed messages.
/// Operates on raw bytes to avoid UTF-8 offset mismatches with binary bodies.
pub fn parse_http(data: &[u8]) -> Vec<HttpMessage> {
    let mut messages = Vec::new();
    let mut remaining = data;

    while !remaining.is_empty() {
        let (header_end, sep_len) = match find_header_end(remaining) {
            Some(result) => result,
            None => break,
        };

        let header_section = &remaining[..header_end];
        let after_headers = &remaining[header_end + sep_len..];

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
            // M10: Validate HTTP method against known methods
            if !KNOWN_METHODS.contains(&parts[0]) {
                break;
            }
            HttpKind::Request {
                method: parts[0].to_string(),
                uri: parts[1].to_string(),
                version: parts.get(2).unwrap_or(&"HTTP/1.1").to_string(),
            }
        };

        // M9: Unfold continuation headers (lines starting with SP/HTAB)
        let mut headers: Vec<(String, String)> = Vec::new();
        for line in lines {
            if (line.starts_with(' ') || line.starts_with('\t')) && !headers.is_empty() {
                // Continuation line: append to previous header value
                if let Some(last) = headers.last_mut() {
                    last.1.push(' ');
                    last.1.push_str(line.trim());
                }
            } else if let Some((key, value)) = line.split_once(':') {
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

        let is_response = matches!(kind, HttpKind::Response { .. });

        let (body, consumed) = if is_chunked {
            match decode_chunked(after_headers) {
                Some((decoded, bytes_consumed)) => (
                    String::from_utf8_lossy(&decoded).into_owned(),
                    bytes_consumed,
                ),
                None => (String::new(), 0),
            }
        } else if let Some(cl) = content_length {
            let len = cl.min(after_headers.len());
            (
                String::from_utf8_lossy(&after_headers[..len]).into_owned(),
                len,
            )
        } else if is_response && !after_headers.is_empty() {
            // H1: Close-delimited response — scan for next HTTP message start
            // before consuming all remaining data.
            let body_len = find_next_http_start(after_headers).unwrap_or(after_headers.len());
            (
                String::from_utf8_lossy(&after_headers[..body_len]).into_owned(),
                body_len,
            )
        } else {
            (String::new(), 0)
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
/// M11: Enforces MAX_CHUNKED_BODY (10 MB) limit on decoded body size.
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
            // L19: Consume trailer headers after zero-size chunk
            // Trailers are header lines terminated by a final CRLF
            while let Some(line_end) = find_crlf(&data[pos..]) {
                pos += line_end + 2;
                if line_end == 0 {
                    // Empty line — end of trailers
                    break;
                }
                // Non-empty line — trailer header, continue
            }
            break;
        }

        // M11: Enforce body size limit
        if decoded.len() + chunk_size > MAX_CHUNKED_BODY {
            return None;
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

    // --- Phase 5 tests ---

    // H1: Close-delimited response followed by another message
    #[test]
    fn close_delimited_response_followed_by_request() {
        let data = b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nbody hereGET /next HTTP/1.1\r\nHost: b\r\n\r\n";
        let msgs = parse_http(data);
        // Should find 2 messages: the response (body up to GET) and the request
        assert_eq!(msgs.len(), 2);
        assert!(matches!(&msgs[0].kind, HttpKind::Response { .. }));
        assert_eq!(msgs[0].body, "body here");
        assert!(matches!(&msgs[1].kind, HttpKind::Request { .. }));
    }

    // H1: Close-delimited response followed by another response
    #[test]
    fn close_delimited_response_then_response() {
        let data = b"HTTP/1.1 200 OK\r\n\r\nfirst bodyHTTP/1.1 404 Not Found\r\nContent-Length: 9\r\n\r\nnot found";
        let msgs = parse_http(data);
        assert_eq!(msgs.len(), 2);
        assert_eq!(msgs[0].body, "first body");
        match &msgs[1].kind {
            HttpKind::Response { status, .. } => assert_eq!(*status, 404),
            _ => panic!("Expected response"),
        }
        assert_eq!(msgs[1].body, "not found");
    }

    // M9: Continuation (folded) headers
    #[test]
    fn parse_folded_headers() {
        let data = b"GET / HTTP/1.1\r\nX-Long-Header: part1\r\n  part2\r\n\tpart3\r\nHost: example.com\r\n\r\n";
        let msgs = parse_http(data);
        assert_eq!(msgs.len(), 1);
        // Folded header should be merged
        let long_hdr = msgs[0]
            .headers
            .iter()
            .find(|(k, _)| k == "X-Long-Header")
            .unwrap();
        assert!(long_hdr.1.contains("part1"));
        assert!(long_hdr.1.contains("part2"));
        assert!(long_hdr.1.contains("part3"));
        // Host should still be separate
        assert!(msgs[0].headers.iter().any(|(k, _)| k == "Host"));
    }

    // M10: Invalid HTTP method is rejected
    #[test]
    fn parse_invalid_method_rejected() {
        let data = b"FOOBAR /path HTTP/1.1\r\nHost: x\r\n\r\n";
        let msgs = parse_http(data);
        assert!(msgs.is_empty());
    }

    // M10: All known methods accepted
    #[test]
    fn parse_known_methods_accepted() {
        for method in &[
            "GET", "HEAD", "POST", "PUT", "DELETE", "CONNECT", "OPTIONS", "TRACE", "PATCH",
        ] {
            let data = format!("{} / HTTP/1.1\r\nHost: x\r\n\r\n", method);
            let msgs = parse_http(data.as_bytes());
            assert_eq!(msgs.len(), 1, "Method {} should be accepted", method);
        }
    }

    // M11: Chunked body exceeding limit returns None
    #[test]
    fn chunked_body_exceeds_limit() {
        // Create a chunk that would decode to > 10MB
        let huge_size = MAX_CHUNKED_BODY + 1;
        let data = format!("{:x}\r\n", huge_size);
        let mut bytes = data.into_bytes();
        bytes.extend(vec![b'A'; huge_size]);
        bytes.extend(b"\r\n0\r\n\r\n");
        assert!(decode_chunked(&bytes).is_none());
    }

    // L18: Bare LF header terminator
    #[test]
    fn parse_bare_lf_headers() {
        let data = b"GET / HTTP/1.1\nHost: example.com\n\nbody";
        let msgs = parse_http(data);
        assert_eq!(msgs.len(), 1);
        assert!(matches!(&msgs[0].kind, HttpKind::Request { .. }));
    }

    // L19: Chunked with trailer headers
    #[test]
    fn chunked_with_trailers() {
        let data = b"5\r\nhello\r\n0\r\nTrailer-Key: value\r\n\r\n";
        let (body, consumed) = decode_chunked(data).unwrap();
        assert_eq!(body, b"hello");
        assert_eq!(consumed, data.len());
    }

    // L19: Chunked with multiple trailer headers
    #[test]
    fn chunked_with_multiple_trailers() {
        let data = b"3\r\nabc\r\n0\r\nX-A: 1\r\nX-B: 2\r\n\r\n";
        let (body, consumed) = decode_chunked(data).unwrap();
        assert_eq!(body, b"abc");
        assert_eq!(consumed, data.len());
    }
}
