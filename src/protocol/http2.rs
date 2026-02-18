use std::collections::HashMap;

use fluke_hpack::Decoder as HpackDecoder;

use super::StreamKey;
use super::http::{HttpKind, HttpMessage};

/// HTTP/2 connection preface sent by the client.
const H2_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/// Frame types we handle.
const FRAME_DATA: u8 = 0x0;
const FRAME_HEADERS: u8 = 0x1;
const FRAME_RST_STREAM: u8 = 0x3;
const FRAME_SETTINGS: u8 = 0x4;
const FRAME_PUSH_PROMISE: u8 = 0x5;
const FRAME_CONTINUATION: u8 = 0x9;

/// Frame flags.
const FLAG_END_STREAM: u8 = 0x1;
const FLAG_END_HEADERS: u8 = 0x4;

/// Safety limits.
const MAX_FRAME_PAYLOAD: usize = 16_777_215; // 2^24 - 1
const MAX_STREAMS_PER_CONN: usize = 1_000;
const MAX_HEADER_BLOCK: usize = 65_536;
const MAX_DATA_PER_STREAM: usize = 1_048_576; // 1 MB
/// M1: Reduced from 10,000 to 2,000 to cap compound memory usage.
/// 2,000 connections * 2 MB * 2 directions = ~8 GB worst case.
const MAX_CONNECTIONS: usize = 2_000;
/// M1: Cap per-direction buffer. Reduced from 16 MB to 2 MB to keep
/// aggregate memory bounded (~8 GB worst case with MAX_CONNECTIONS).
const MAX_DIRECTION_BUF: usize = 2 * 1024 * 1024; // 2 MB

/// Direction of data flow within a connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum H2Direction {
    ClientToServer,
    ServerToClient,
}

/// Tracks HTTP/2 connections and parses frames into `HttpMessage`s.
pub struct H2Tracker {
    connections: HashMap<StreamKey, H2Connection>,
    tick: u64,
}

struct H2Connection {
    /// Per-direction HPACK decoders.
    client_decoder: HpackDecoder<'static>,
    server_decoder: HpackDecoder<'static>,
    /// Per-stream state, keyed by HTTP/2 stream ID.
    streams: HashMap<u32, H2Stream>,
    /// Per-direction unprocessed buffers.
    client_buf: Vec<u8>,
    server_buf: Vec<u8>,
    /// Whether HTTP/2 has been detected (None = unknown, Some(true) = yes, Some(false) = no).
    detected: Option<bool>,
    /// Monotonic tick for LRU eviction.
    last_active: u64,
    /// M3: Accumulates header block fragments for discarded streams (rejected at
    /// stream limit) or PUSH_PROMISE frames that span multiple CONTINUATION
    /// frames. HPACK is stateful — every header block must be decoded even if
    /// the headers are discarded, otherwise the dynamic table becomes corrupted.
    /// Uses a HashMap to track multiple concurrent discarded streams.
    discard_header_bufs: HashMap<u32, (H2Direction, Vec<u8>)>,
}

struct H2Stream {
    /// Pseudo-headers (:method, :path, :status, :authority, :scheme).
    pseudo_headers: Vec<(String, String)>,
    /// Regular headers.
    headers: Vec<(String, String)>,
    /// Accumulates HEADERS/CONTINUATION header block fragments before END_HEADERS.
    header_buf: Vec<u8>,
    /// Accumulated DATA frame body.
    data: Vec<u8>,
    /// Whether END_HEADERS has been seen (header block is complete).
    end_headers: bool,
    /// Whether END_STREAM was set on the HEADERS frame (no body expected).
    end_stream_headers: bool,
    /// Whether END_STREAM was set on a DATA frame.
    end_stream_data: bool,
    /// M2: Set when accumulated header block exceeds MAX_HEADER_BLOCK.
    /// When true, HPACK decoding is skipped to avoid partial dynamic table
    /// mutation from a truncated header block.
    header_overflow: bool,
}

impl H2Stream {
    fn new() -> Self {
        H2Stream {
            pseudo_headers: Vec::new(),
            headers: Vec::new(),
            header_buf: Vec::new(),
            data: Vec::new(),
            end_headers: false,
            end_stream_headers: false,
            end_stream_data: false,
            header_overflow: false,
        }
    }
}

impl H2Connection {
    fn new() -> Self {
        H2Connection {
            client_decoder: HpackDecoder::new(),
            server_decoder: HpackDecoder::new(),
            streams: HashMap::new(),
            client_buf: Vec::new(),
            server_buf: Vec::new(),
            detected: None,
            last_active: 0,
            discard_header_bufs: HashMap::new(),
        }
    }
}

impl Default for H2Tracker {
    fn default() -> Self {
        Self::new()
    }
}

impl H2Tracker {
    pub fn new() -> Self {
        H2Tracker {
            connections: HashMap::new(),
            tick: 0,
        }
    }

    /// Feed decrypted stream payload from one direction of a connection.
    /// Returns completed HTTP messages (if any).
    pub fn process(
        &mut self,
        key: &StreamKey,
        payload: &[u8],
        direction: H2Direction,
    ) -> Vec<HttpMessage> {
        if payload.is_empty() {
            return vec![];
        }

        self.tick += 1;

        // Evict least-recently-active if at capacity for a new connection
        if !self.connections.contains_key(key) && self.connections.len() >= MAX_CONNECTIONS {
            let oldest_key = self
                .connections
                .iter()
                .min_by_key(|(_, conn)| conn.last_active)
                .map(|(key, _)| key.clone());
            if let Some(old_key) = oldest_key {
                self.connections.remove(&old_key);
            }
        }

        let tick = self.tick;
        let conn = self
            .connections
            .entry(key.clone())
            .or_insert_with(H2Connection::new);
        conn.last_active = tick;

        // Append to per-direction buffer
        let buf = match direction {
            H2Direction::ClientToServer => &mut conn.client_buf,
            H2Direction::ServerToClient => &mut conn.server_buf,
        };
        // M1: Cap per-direction buffer size to prevent unbounded growth
        if buf.len() + payload.len() > MAX_DIRECTION_BUF {
            buf.clear();
            return vec![];
        }
        buf.extend_from_slice(payload);

        // Check for HTTP/2 detection on either direction buffer (M14)
        if conn.detected.is_none() {
            // Check client buffer first (most common), then server
            for buf in [&mut conn.client_buf as &mut Vec<u8>, &mut conn.server_buf] {
                if buf.len() >= H2_PREFACE.len() {
                    if buf.starts_with(H2_PREFACE) {
                        conn.detected = Some(true);
                        buf.drain(..H2_PREFACE.len());
                        break;
                    } else {
                        // Not a match — only reject if this is the client buffer
                        // (server direction is less likely to have preface)
                    }
                } else if !buf.is_empty() && !H2_PREFACE.starts_with(buf.as_slice()) {
                    // Partial buffer doesn't match preface prefix
                }
            }
            // If client buffer has enough data and doesn't match, or partial
            // buffer doesn't match preface prefix, reject.
            if conn.detected.is_none()
                && (conn.client_buf.len() >= H2_PREFACE.len()
                    || (!conn.client_buf.is_empty() && !H2_PREFACE.starts_with(&conn.client_buf)))
            {
                conn.detected = Some(false);
            }
        }

        match conn.detected {
            Some(true) => {}
            Some(false) => return vec![],
            None => return vec![],
        }

        // Parse frames from the buffer for this direction
        Self::drain_frames(conn, direction)
    }

    /// Parse complete HTTP/2 frames from the direction buffer, returning any completed messages.
    /// M8: Uses a cursor offset instead of per-frame drain for O(n) total cost.
    fn drain_frames(conn: &mut H2Connection, direction: H2Direction) -> Vec<HttpMessage> {
        let mut messages = Vec::new();
        let mut cursor = 0;

        loop {
            let buf = match direction {
                H2Direction::ClientToServer => &conn.client_buf,
                H2Direction::ServerToClient => &conn.server_buf,
            };

            let remaining = buf.len() - cursor;

            // Need at least 9 bytes for a frame header
            if remaining < 9 {
                break;
            }

            // Parse frame header
            let payload_len = ((buf[cursor] as usize) << 16)
                | ((buf[cursor + 1] as usize) << 8)
                | (buf[cursor + 2] as usize);
            let frame_type = buf[cursor + 3];
            let flags = buf[cursor + 4];
            let stream_id = u32::from_be_bytes([
                buf[cursor + 5] & 0x7F,
                buf[cursor + 6],
                buf[cursor + 7],
                buf[cursor + 8],
            ]);

            // Safety check on payload size
            if payload_len > MAX_FRAME_PAYLOAD {
                // Malformed — discard entire buffer
                cursor = buf.len();
                break;
            }

            // Check if we have the complete frame
            let total = 9 + payload_len;
            if remaining < total {
                break;
            }

            // Extract frame payload
            let frame_payload = buf[cursor + 9..cursor + total].to_vec();

            // Advance cursor past this frame
            cursor += total;

            // Process frame by type
            match frame_type {
                FRAME_HEADERS => {
                    let end_stream = flags & FLAG_END_STREAM != 0;
                    let end_headers = flags & FLAG_END_HEADERS != 0;

                    if stream_id == 0 {
                        continue;
                    }

                    // C1/H2: Allow existing streams even at limit. For new streams
                    // at limit, still decode HPACK to keep state consistent.
                    let is_new = !conn.streams.contains_key(&stream_id);
                    let at_limit = conn.streams.len() >= MAX_STREAMS_PER_CONN;

                    let header_block = parse_headers_payload(&frame_payload, flags);

                    if is_new && at_limit {
                        // Must decode HPACK to maintain state, but discard result.
                        if end_headers {
                            let decoder = match direction {
                                H2Direction::ClientToServer => &mut conn.client_decoder,
                                H2Direction::ServerToClient => &mut conn.server_decoder,
                            };
                            let _ = decoder.decode(header_block);
                        } else {
                            // No END_HEADERS — accumulate fragments for HPACK
                            // decode when the final CONTINUATION arrives.
                            let mut buf = Vec::new();
                            if header_block.len() <= MAX_HEADER_BLOCK {
                                buf.extend_from_slice(header_block);
                            }
                            conn.discard_header_bufs.insert(stream_id, (direction, buf));
                        }
                        continue;
                    }

                    let stream = conn.streams.entry(stream_id).or_insert_with(H2Stream::new);

                    // M2: Track header block overflow to avoid partial HPACK decode
                    if stream.header_buf.len() + header_block.len() <= MAX_HEADER_BLOCK {
                        stream.header_buf.extend_from_slice(header_block);
                    } else {
                        stream.header_overflow = true;
                    }

                    if end_stream {
                        stream.end_stream_headers = true;
                    }

                    if end_headers {
                        stream.end_headers = true;
                        if !stream.header_overflow {
                            let decoder = match direction {
                                H2Direction::ClientToServer => &mut conn.client_decoder,
                                H2Direction::ServerToClient => &mut conn.server_decoder,
                            };
                            decode_headers(stream, decoder);
                        }

                        if stream.end_stream_headers {
                            if let Some(msg) = build_message(stream) {
                                messages.push(msg);
                            }
                            conn.streams.remove(&stream_id);
                        }
                    }
                }
                FRAME_CONTINUATION => {
                    if let Some(stream) = conn.streams.get_mut(&stream_id) {
                        if !stream.end_headers {
                            // M2: Track overflow instead of silently dropping
                            if stream.header_buf.len() + frame_payload.len() <= MAX_HEADER_BLOCK
                                && !stream.header_overflow
                            {
                                stream.header_buf.extend_from_slice(&frame_payload);
                            } else {
                                stream.header_overflow = true;
                            }

                            let end_headers = flags & FLAG_END_HEADERS != 0;
                            if end_headers {
                                stream.end_headers = true;
                                if !stream.header_overflow {
                                    let decoder = match direction {
                                        H2Direction::ClientToServer => &mut conn.client_decoder,
                                        H2Direction::ServerToClient => &mut conn.server_decoder,
                                    };
                                    decode_headers(stream, decoder);
                                }

                                if stream.end_stream_headers {
                                    if let Some(msg) = build_message(stream) {
                                        messages.push(msg);
                                    }
                                    conn.streams.remove(&stream_id);
                                }
                            }
                        }
                    } else {
                        // CONTINUATION for a discarded stream or PUSH_PROMISE —
                        // accumulate fragments and decode HPACK when complete.
                        let end_headers = flags & FLAG_END_HEADERS != 0;
                        // M3: Use HashMap to track multiple discarded streams
                        if let Some((discard_dir, buf)) =
                            conn.discard_header_bufs.get_mut(&stream_id)
                        {
                            let discard_dir = *discard_dir;
                            if buf.len() + frame_payload.len() <= MAX_HEADER_BLOCK {
                                buf.extend_from_slice(&frame_payload);
                            }
                            if end_headers {
                                let decoder = match discard_dir {
                                    H2Direction::ClientToServer => &mut conn.client_decoder,
                                    H2Direction::ServerToClient => &mut conn.server_decoder,
                                };
                                let _ = decoder.decode(buf);
                                conn.discard_header_bufs.remove(&stream_id);
                            }
                            continue;
                        }
                        // Standalone CONTINUATION without a tracked discard buffer
                        if end_headers {
                            let decoder = match direction {
                                H2Direction::ClientToServer => &mut conn.client_decoder,
                                H2Direction::ServerToClient => &mut conn.server_decoder,
                            };
                            let _ = decoder.decode(&frame_payload);
                        }
                    }
                }
                FRAME_DATA => {
                    let end_stream = flags & FLAG_END_STREAM != 0;

                    if let Some(stream) = conn.streams.get_mut(&stream_id) {
                        // Strip padding if PADDED flag is set
                        let data = if flags & 0x8 != 0 && !frame_payload.is_empty() {
                            let pad_len = frame_payload[0] as usize;
                            if pad_len < frame_payload.len() {
                                &frame_payload[1..frame_payload.len() - pad_len]
                            } else {
                                &[]
                            }
                        } else {
                            &frame_payload
                        };

                        if stream.data.len() + data.len() <= MAX_DATA_PER_STREAM {
                            stream.data.extend_from_slice(data);
                        }

                        if end_stream {
                            stream.end_stream_data = true;
                            if let Some(msg) = build_message(stream) {
                                messages.push(msg);
                            }
                            conn.streams.remove(&stream_id);
                        }
                    }
                }
                FRAME_RST_STREAM => {
                    // M13: Remove stream on RST_STREAM
                    conn.streams.remove(&stream_id);
                }
                FRAME_PUSH_PROMISE => {
                    // C2: Parse PUSH_PROMISE to maintain HPACK state.
                    // Format: [Pad Length?] [R + Promised Stream ID (4)] [Header Block Fragment] [Padding?]
                    let mut offset = 0;
                    let mut end = frame_payload.len();

                    // Handle padding
                    if flags & 0x8 != 0 {
                        if frame_payload.is_empty() {
                            continue;
                        }
                        let pad_len = frame_payload[0] as usize;
                        offset += 1;
                        if pad_len >= end - offset {
                            continue;
                        }
                        end -= pad_len;
                    }

                    // Skip promised stream ID (4 bytes)
                    if offset + 4 > end {
                        continue;
                    }
                    offset += 4;

                    let header_block = &frame_payload[offset..end];

                    // Decode HPACK (discard headers — we don't track pushed streams)
                    let end_headers = flags & FLAG_END_HEADERS != 0;
                    if end_headers {
                        let decoder = match direction {
                            H2Direction::ClientToServer => &mut conn.client_decoder,
                            H2Direction::ServerToClient => &mut conn.server_decoder,
                        };
                        let _ = decoder.decode(header_block);
                    } else {
                        // No END_HEADERS — accumulate fragments for HPACK
                        // decode when the final CONTINUATION arrives.
                        let mut buf = Vec::new();
                        if header_block.len() <= MAX_HEADER_BLOCK {
                            buf.extend_from_slice(header_block);
                        }
                        conn.discard_header_bufs.insert(stream_id, (direction, buf));
                    }
                }
                FRAME_SETTINGS => {
                    // SETTINGS frames are on stream 0; nothing to extract for our purposes.
                }
                _ => {
                    // PRIORITY, PING, GOAWAY, WINDOW_UPDATE —
                    // not needed for basic HTTP message extraction.
                }
            }
        }

        // M8: Single drain at the end — O(remaining) once, not per-frame
        if cursor > 0 {
            match direction {
                H2Direction::ClientToServer => {
                    conn.client_buf.drain(..cursor);
                }
                H2Direction::ServerToClient => {
                    conn.server_buf.drain(..cursor);
                }
            }
        }

        messages
    }
}

/// Parse HEADERS frame payload, stripping optional padding and priority fields.
/// Returns the header block fragment.
fn parse_headers_payload(payload: &[u8], flags: u8) -> &[u8] {
    let mut offset = 0;
    let mut end = payload.len();

    // PADDED flag (0x8)
    if flags & 0x8 != 0 {
        if payload.is_empty() {
            return &[];
        }
        let pad_len = payload[0] as usize;
        offset += 1;
        if pad_len >= end - offset {
            return &[];
        }
        end -= pad_len;
    }

    // PRIORITY flag (0x20)
    if flags & 0x20 != 0 {
        if offset + 5 > end {
            return &[];
        }
        offset += 5; // 4 bytes stream dependency + 1 byte weight
    }

    if offset > end {
        return &[];
    }

    &payload[offset..end]
}

/// Decode accumulated HPACK header block into pseudo-headers and regular headers.
fn decode_headers(stream: &mut H2Stream, decoder: &mut HpackDecoder) {
    let header_block = std::mem::take(&mut stream.header_buf);
    match decoder.decode(&header_block) {
        Ok(decoded) => {
            for (name, value) in decoded {
                let name_str = String::from_utf8_lossy(&name).into_owned();
                let value_str = String::from_utf8_lossy(&value).into_owned();
                if name_str.starts_with(':') {
                    stream.pseudo_headers.push((name_str, value_str));
                } else {
                    stream.headers.push((name_str, value_str));
                }
            }
        }
        Err(_) => {
            // HPACK decode failure — leave headers empty
        }
    }
}

/// Build an HttpMessage from a completed H2Stream.
fn build_message(stream: &H2Stream) -> Option<HttpMessage> {
    // Determine if this is a request or response from pseudo-headers
    let method = stream
        .pseudo_headers
        .iter()
        .find(|(k, _)| k == ":method")
        .map(|(_, v)| v.clone());
    let path = stream
        .pseudo_headers
        .iter()
        .find(|(k, _)| k == ":path")
        .map(|(_, v)| v.clone());
    let status = stream
        .pseudo_headers
        .iter()
        .find(|(k, _)| k == ":status")
        .map(|(_, v)| v.clone());

    let kind = if let Some(status_str) = status {
        let code = status_str.parse::<u16>().unwrap_or(0);
        HttpKind::Response {
            version: "HTTP/2".to_string(),
            status: code,
            reason: String::new(),
        }
    } else if let (Some(method), Some(path)) = (method, path) {
        HttpKind::Request {
            method,
            uri: path,
            version: "HTTP/2".to_string(),
        }
    } else {
        return None;
    };

    let body = String::from_utf8_lossy(&stream.data).into_owned();

    Some(HttpMessage {
        kind,
        headers: stream.headers.clone(),
        body,
        smuggling_risk: false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn test_key() -> StreamKey {
        StreamKey::new(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            1234,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            443,
        )
    }

    /// Build a raw HTTP/2 frame.
    fn build_frame(frame_type: u8, flags: u8, stream_id: u32, payload: &[u8]) -> Vec<u8> {
        let len = payload.len();
        let mut frame = Vec::with_capacity(9 + len);
        frame.push((len >> 16) as u8);
        frame.push((len >> 8) as u8);
        frame.push(len as u8);
        frame.push(frame_type);
        frame.push(flags);
        let sid = stream_id & 0x7FFFFFFF;
        frame.extend_from_slice(&sid.to_be_bytes());
        frame.extend_from_slice(payload);
        frame
    }

    /// Encode a simple header list using HPACK literal encoding (no indexing).
    fn hpack_encode_headers(headers: &[(&str, &str)]) -> Vec<u8> {
        use fluke_hpack::Encoder;
        let mut encoder = Encoder::new();
        let h: Vec<(Vec<u8>, Vec<u8>)> = headers
            .iter()
            .map(|(k, v)| (k.as_bytes().to_vec(), v.as_bytes().to_vec()))
            .collect();
        let refs: Vec<(&[u8], &[u8])> = h
            .iter()
            .map(|(k, v)| (k.as_slice(), v.as_slice()))
            .collect();
        encoder.encode(refs.into_iter())
    }

    #[test]
    fn connection_preface_detection() {
        let mut tracker = H2Tracker::new();
        let key = test_key();

        // Send client connection preface
        let msgs = tracker.process(&key, H2_PREFACE, H2Direction::ClientToServer);
        assert!(msgs.is_empty());

        // Connection should be detected as HTTP/2
        let conn = tracker.connections.get(&key).unwrap();
        assert_eq!(conn.detected, Some(true));
    }

    #[test]
    fn non_h2_detection() {
        let mut tracker = H2Tracker::new();
        let key = test_key();

        // Send something that's not a preface
        let msgs = tracker.process(&key, b"GET / HTTP/1.1\r\n", H2Direction::ClientToServer);
        assert!(msgs.is_empty());

        let conn = tracker.connections.get(&key).unwrap();
        assert_eq!(conn.detected, Some(false));
    }

    #[test]
    fn headers_with_end_stream_emits_request() {
        let mut tracker = H2Tracker::new();
        let key = test_key();

        // Send preface
        tracker.process(&key, H2_PREFACE, H2Direction::ClientToServer);

        // Build HEADERS frame with END_STREAM + END_HEADERS
        let header_block = hpack_encode_headers(&[
            (":method", "GET"),
            (":path", "/index.html"),
            (":scheme", "https"),
            (":authority", "example.com"),
            ("user-agent", "test/1.0"),
        ]);
        let frame = build_frame(
            FRAME_HEADERS,
            FLAG_END_STREAM | FLAG_END_HEADERS,
            1,
            &header_block,
        );

        let msgs = tracker.process(&key, &frame, H2Direction::ClientToServer);
        assert_eq!(msgs.len(), 1);
        match &msgs[0].kind {
            HttpKind::Request {
                method,
                uri,
                version,
            } => {
                assert_eq!(method, "GET");
                assert_eq!(uri, "/index.html");
                assert_eq!(version, "HTTP/2");
            }
            _ => panic!("Expected request"),
        }
        assert_eq!(msgs[0].headers.len(), 1); // only user-agent (all : prefixed are pseudo)
        assert_eq!(msgs[0].headers[0].0, "user-agent");
        assert_eq!(msgs[0].body, "");
    }

    #[test]
    fn response_with_data_frames() {
        let mut tracker = H2Tracker::new();
        let key = test_key();

        // Preface
        tracker.process(&key, H2_PREFACE, H2Direction::ClientToServer);

        // Response HEADERS (no END_STREAM)
        let header_block =
            hpack_encode_headers(&[(":status", "200"), ("content-type", "text/plain")]);
        let headers_frame = build_frame(
            FRAME_HEADERS,
            FLAG_END_HEADERS, // no END_STREAM
            1,
            &header_block,
        );

        // DATA frame with END_STREAM
        let data_frame = build_frame(FRAME_DATA, FLAG_END_STREAM, 1, b"Hello, World!");

        // Send headers first (from server direction)
        let msgs = tracker.process(&key, &headers_frame, H2Direction::ServerToClient);
        assert!(msgs.is_empty()); // no END_STREAM yet

        // Send data
        let msgs = tracker.process(&key, &data_frame, H2Direction::ServerToClient);
        assert_eq!(msgs.len(), 1);
        match &msgs[0].kind {
            HttpKind::Response {
                status, version, ..
            } => {
                assert_eq!(*status, 200);
                assert_eq!(version, "HTTP/2");
            }
            _ => panic!("Expected response"),
        }
        assert_eq!(msgs[0].body, "Hello, World!");
    }

    #[test]
    fn continuation_frame() {
        let mut tracker = H2Tracker::new();
        let key = test_key();

        tracker.process(&key, H2_PREFACE, H2Direction::ClientToServer);

        // Build a HEADERS frame without END_HEADERS, then CONTINUATION with END_HEADERS
        let header_block = hpack_encode_headers(&[
            (":method", "POST"),
            (":path", "/api"),
            (":scheme", "https"),
            ("content-type", "application/json"),
        ]);

        // Split the header block in half
        let mid = header_block.len() / 2;
        let part1 = &header_block[..mid];
        let part2 = &header_block[mid..];

        // HEADERS frame without END_HEADERS, with END_STREAM
        let headers_frame = build_frame(FRAME_HEADERS, FLAG_END_STREAM, 1, part1);
        let msgs = tracker.process(&key, &headers_frame, H2Direction::ClientToServer);
        assert!(msgs.is_empty()); // waiting for END_HEADERS

        // CONTINUATION frame with END_HEADERS
        let cont_frame = build_frame(FRAME_CONTINUATION, FLAG_END_HEADERS, 1, part2);
        let msgs = tracker.process(&key, &cont_frame, H2Direction::ClientToServer);
        assert_eq!(msgs.len(), 1);
        match &msgs[0].kind {
            HttpKind::Request { method, uri, .. } => {
                assert_eq!(method, "POST");
                assert_eq!(uri, "/api");
            }
            _ => panic!("Expected request"),
        }
    }

    #[test]
    fn settings_frame_ignored() {
        let mut tracker = H2Tracker::new();
        let key = test_key();

        tracker.process(&key, H2_PREFACE, H2Direction::ClientToServer);

        // SETTINGS frame (stream_id=0)
        let settings = build_frame(FRAME_SETTINGS, 0, 0, &[0, 3, 0, 0, 0, 100]);
        let msgs = tracker.process(&key, &settings, H2Direction::ClientToServer);
        assert!(msgs.is_empty());
    }

    #[test]
    fn unknown_frame_type_ignored() {
        let mut tracker = H2Tracker::new();
        let key = test_key();

        tracker.process(&key, H2_PREFACE, H2Direction::ClientToServer);

        // Unknown frame type 0xFF
        let frame = build_frame(0xFF, 0, 1, b"whatever");
        let msgs = tracker.process(&key, &frame, H2Direction::ClientToServer);
        assert!(msgs.is_empty());
    }

    #[test]
    fn multiple_streams_interleaved() {
        let mut tracker = H2Tracker::new();
        let key = test_key();

        tracker.process(&key, H2_PREFACE, H2Direction::ClientToServer);

        // Stream 1: GET request
        let h1 = hpack_encode_headers(&[(":method", "GET"), (":path", "/a"), (":scheme", "https")]);
        let f1 = build_frame(FRAME_HEADERS, FLAG_END_STREAM | FLAG_END_HEADERS, 1, &h1);

        // Stream 3: GET request
        let h3 = hpack_encode_headers(&[(":method", "GET"), (":path", "/b"), (":scheme", "https")]);
        let f3 = build_frame(FRAME_HEADERS, FLAG_END_STREAM | FLAG_END_HEADERS, 3, &h3);

        // Send both in one payload
        let mut payload = f1;
        payload.extend_from_slice(&f3);
        let msgs = tracker.process(&key, &payload, H2Direction::ClientToServer);
        assert_eq!(msgs.len(), 2);
    }

    #[test]
    fn http1_fallback_returns_empty() {
        let mut tracker = H2Tracker::new();
        let key = test_key();

        // Send HTTP/1.1 data
        let msgs = tracker.process(
            &key,
            b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
            H2Direction::ClientToServer,
        );
        assert!(msgs.is_empty());

        // Subsequent data also returns empty
        let msgs = tracker.process(&key, b"more data", H2Direction::ClientToServer);
        assert!(msgs.is_empty());
    }

    #[test]
    fn data_frame_with_padding() {
        let mut tracker = H2Tracker::new();
        let key = test_key();

        tracker.process(&key, H2_PREFACE, H2Direction::ClientToServer);

        // Send response headers first
        let header_block = hpack_encode_headers(&[(":status", "200")]);
        let headers_frame = build_frame(FRAME_HEADERS, FLAG_END_HEADERS, 1, &header_block);
        tracker.process(&key, &headers_frame, H2Direction::ServerToClient);

        // DATA frame with PADDED flag (0x8) and END_STREAM
        // Format: [pad_length(1)] [data] [padding]
        let mut padded_payload = vec![3]; // 3 bytes of padding
        padded_payload.extend_from_slice(b"body");
        padded_payload.extend_from_slice(&[0, 0, 0]); // 3 bytes padding
        let data_frame = build_frame(FRAME_DATA, FLAG_END_STREAM | 0x8, 1, &padded_payload);

        let msgs = tracker.process(&key, &data_frame, H2Direction::ServerToClient);
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].body, "body");
    }

    #[test]
    fn parse_headers_payload_plain() {
        let payload = b"header block data";
        let result = parse_headers_payload(payload, 0);
        assert_eq!(result, payload);
    }

    #[test]
    fn parse_headers_payload_with_padding() {
        // flags = 0x8 (PADDED)
        // payload: [pad_len=2] [header data] [2 bytes padding]
        let mut payload = vec![2]; // pad_len
        payload.extend_from_slice(b"headers");
        payload.extend_from_slice(&[0, 0]); // padding
        let result = parse_headers_payload(&payload, 0x8);
        assert_eq!(result, b"headers");
    }

    #[test]
    fn parse_headers_payload_with_priority() {
        // flags = 0x20 (PRIORITY)
        // payload: [4 bytes stream dep] [1 byte weight] [header data]
        let mut payload = vec![0, 0, 0, 0, 255]; // stream dep + weight
        payload.extend_from_slice(b"headers");
        let result = parse_headers_payload(&payload, 0x20);
        assert_eq!(result, b"headers");
    }

    #[test]
    fn pseudo_headers_not_in_regular_headers() {
        let mut tracker = H2Tracker::new();
        let key = test_key();

        tracker.process(&key, H2_PREFACE, H2Direction::ClientToServer);

        let header_block = hpack_encode_headers(&[
            (":status", "404"),
            ("content-type", "text/html"),
            ("server", "test"),
        ]);
        let frame = build_frame(
            FRAME_HEADERS,
            FLAG_END_STREAM | FLAG_END_HEADERS,
            1,
            &header_block,
        );
        let msgs = tracker.process(&key, &frame, H2Direction::ServerToClient);
        assert_eq!(msgs.len(), 1);

        // Regular headers should not include :status
        for (k, _) in &msgs[0].headers {
            assert!(!k.starts_with(':'));
        }
        assert_eq!(msgs[0].headers.len(), 2); // content-type, server
    }

    #[test]
    fn hpack_consistent_after_stream_limit() {
        let mut tracker = H2Tracker::new();
        let key = test_key();

        tracker.process(&key, H2_PREFACE, H2Direction::ClientToServer);

        // Fill up to MAX_STREAMS_PER_CONN
        for i in 1..=MAX_STREAMS_PER_CONN {
            let sid = (i * 2 + 1) as u32; // odd stream IDs
            let header_block = hpack_encode_headers(&[
                (":method", "GET"),
                (":path", &format!("/stream/{}", i)),
                (":scheme", "https"),
            ]);
            // No END_STREAM so streams stay open
            let frame = build_frame(FRAME_HEADERS, FLAG_END_HEADERS, sid, &header_block);
            tracker.process(&key, &frame, H2Direction::ClientToServer);
        }

        // At limit now. Try to add one more — should not corrupt HPACK
        let over_limit_block = hpack_encode_headers(&[
            (":method", "POST"),
            (":path", "/over-limit"),
            (":scheme", "https"),
        ]);
        let over_limit_sid = (MAX_STREAMS_PER_CONN * 2 + 3) as u32;
        let frame = build_frame(
            FRAME_HEADERS,
            FLAG_END_STREAM | FLAG_END_HEADERS,
            over_limit_sid,
            &over_limit_block,
        );
        // This should NOT add the stream but SHOULD decode HPACK
        let msgs = tracker.process(&key, &frame, H2Direction::ClientToServer);
        assert!(msgs.is_empty()); // discarded

        // Now close one existing stream so we can add another
        let rst_frame = build_frame(FRAME_RST_STREAM, 0, 3, &[0, 0, 0, 0]);
        tracker.process(&key, &rst_frame, H2Direction::ClientToServer);

        // Add a new stream — HPACK should still be consistent
        let new_block = hpack_encode_headers(&[
            (":method", "GET"),
            (":path", "/after-limit"),
            (":scheme", "https"),
        ]);
        let new_sid = (MAX_STREAMS_PER_CONN * 2 + 5) as u32;
        let frame = build_frame(
            FRAME_HEADERS,
            FLAG_END_STREAM | FLAG_END_HEADERS,
            new_sid,
            &new_block,
        );
        let msgs = tracker.process(&key, &frame, H2Direction::ClientToServer);
        assert_eq!(msgs.len(), 1);
        match &msgs[0].kind {
            HttpKind::Request { uri, .. } => assert_eq!(uri, "/after-limit"),
            _ => panic!("Expected request"),
        }
    }

    #[test]
    fn rst_stream_removes_stream() {
        let mut tracker = H2Tracker::new();
        let key = test_key();

        tracker.process(&key, H2_PREFACE, H2Direction::ClientToServer);

        // Create a stream (no END_STREAM)
        let header_block = hpack_encode_headers(&[(":status", "200")]);
        let frame = build_frame(FRAME_HEADERS, FLAG_END_HEADERS, 1, &header_block);
        tracker.process(&key, &frame, H2Direction::ServerToClient);

        // RST_STREAM should remove it
        let rst = build_frame(FRAME_RST_STREAM, 0, 1, &[0, 0, 0, 8]); // CANCEL
        tracker.process(&key, &rst, H2Direction::ServerToClient);

        // Sending DATA on that stream should produce nothing
        let data = build_frame(FRAME_DATA, FLAG_END_STREAM, 1, b"orphan");
        let msgs = tracker.process(&key, &data, H2Direction::ServerToClient);
        assert!(msgs.is_empty());
    }

    #[test]
    fn push_promise_decoded_for_hpack() {
        let mut tracker = H2Tracker::new();
        let key = test_key();

        tracker.process(&key, H2_PREFACE, H2Direction::ClientToServer);

        // Build PUSH_PROMISE frame: [Promised-Stream-ID (4)] + header block
        let header_block = hpack_encode_headers(&[
            (":method", "GET"),
            (":path", "/pushed"),
            (":scheme", "https"),
            (":authority", "example.com"),
        ]);
        let mut pp_payload = Vec::new();
        pp_payload.extend_from_slice(&2u32.to_be_bytes()); // promised stream ID = 2
        pp_payload.extend_from_slice(&header_block);

        let frame = build_frame(FRAME_PUSH_PROMISE, FLAG_END_HEADERS, 1, &pp_payload);
        let msgs = tracker.process(&key, &frame, H2Direction::ServerToClient);
        assert!(msgs.is_empty()); // PUSH_PROMISE doesn't emit messages

        // Verify HPACK state is intact by sending another HEADERS
        let header_block2 = hpack_encode_headers(&[(":status", "200")]);
        let frame2 = build_frame(
            FRAME_HEADERS,
            FLAG_END_STREAM | FLAG_END_HEADERS,
            1,
            &header_block2,
        );
        let msgs = tracker.process(&key, &frame2, H2Direction::ServerToClient);
        assert_eq!(msgs.len(), 1);
    }

    #[test]
    fn existing_stream_headers_at_limit() {
        let mut tracker = H2Tracker::new();
        let key = test_key();

        tracker.process(&key, H2_PREFACE, H2Direction::ClientToServer);

        // Create streams up to limit
        for i in 1..=MAX_STREAMS_PER_CONN {
            let sid = (i * 2 + 1) as u32;
            let hb =
                hpack_encode_headers(&[(":method", "GET"), (":path", "/"), (":scheme", "https")]);
            let frame = build_frame(FRAME_HEADERS, FLAG_END_HEADERS, sid, &hb);
            tracker.process(&key, &frame, H2Direction::ClientToServer);
        }

        // Sending HEADERS on an existing stream should still work at limit
        let existing_sid = 3u32;
        let hb = hpack_encode_headers(&[(":status", "200")]);
        let frame = build_frame(
            FRAME_HEADERS,
            FLAG_END_STREAM | FLAG_END_HEADERS,
            existing_sid,
            &hb,
        );
        let msgs = tracker.process(&key, &frame, H2Direction::ServerToClient);
        // This is a response on an existing stream — should be allowed
        assert_eq!(msgs.len(), 1);
    }
}
