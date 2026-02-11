use std::collections::HashMap;

use crate::protocol::{ParsedPacket, StreamKey};

/// Tracks TCP streams and reassembles payloads.
pub struct StreamTable {
    streams: HashMap<StreamKey, StreamState>,
    max_streams: usize,
    max_stream_bytes: usize,
}

struct StreamState {
    payload: Vec<u8>,
    packets_seen: usize,
    finished: bool,
}

/// Reassembled stream data emitted when a stream has enough data to match against.
pub struct StreamData {
    pub key: StreamKey,
    pub payload: Vec<u8>,
}

impl StreamData {
    pub fn payload_str(&self) -> String {
        String::from_utf8_lossy(&self.payload).into_owned()
    }
}

impl StreamTable {
    pub fn new() -> Self {
        StreamTable {
            streams: HashMap::new(),
            max_streams: 10_000,
            max_stream_bytes: 1_048_576, // 1 MB per stream
        }
    }

    /// Process a TCP packet. Returns stream data when the stream has payload
    /// to match against (on PSH or when the stream closes).
    pub fn process(&mut self, packet: &ParsedPacket) -> Option<StreamData> {
        let key = packet.stream_key()?;
        let flags = packet.tcp_flags?;

        // RST — tear down and emit what we have
        if flags.rst {
            return self.streams.remove(&key).and_then(|state| {
                if state.payload.is_empty() {
                    None
                } else {
                    Some(StreamData {
                        key,
                        payload: state.payload,
                    })
                }
            });
        }

        // SYN without ACK — new connection
        if flags.syn && !flags.ack {
            self.streams.insert(
                key.clone(),
                StreamState {
                    payload: Vec::new(),
                    packets_seen: 0,
                    finished: false,
                },
            );
            return None;
        }

        // Skip if at capacity and this is a new stream
        if !self.streams.contains_key(&key) && self.streams.len() >= self.max_streams {
            return None;
        }

        let state = self.streams.entry(key.clone()).or_insert_with(|| StreamState {
            payload: Vec::new(),
            packets_seen: 0,
            finished: false,
        });

        // Append payload
        if !packet.payload.is_empty() && state.payload.len() < self.max_stream_bytes {
            let remaining = self.max_stream_bytes - state.payload.len();
            let to_copy = packet.payload.len().min(remaining);
            state.payload.extend_from_slice(&packet.payload[..to_copy]);
        }
        state.packets_seen += 1;

        // Emit on PSH (data ready) or FIN (closing)
        let should_emit = flags.psh || flags.fin;

        if flags.fin {
            state.finished = true;
        }

        if should_emit && !state.payload.is_empty() {
            let data = StreamData {
                key: key.clone(),
                payload: state.payload.clone(),
            };

            if state.finished {
                self.streams.remove(&key);
            }

            Some(data)
        } else {
            None
        }
    }
}
