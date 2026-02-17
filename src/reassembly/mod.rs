use std::collections::HashMap;
use std::net::IpAddr;

use crate::protocol::{ParsedPacket, StreamKey};

/// Tracks TCP streams and reassembles payloads.
pub struct StreamTable {
    streams: HashMap<StreamKey, StreamState>,
    max_streams: usize,
    max_stream_bytes: usize,
    /// Monotonic counter incremented on each process() call.
    tick: u64,
}

struct StreamState {
    payload: Vec<u8>,
    packets_seen: usize,
    finished: bool,
    /// Byte offset up to which we've already emitted data.
    emitted_offset: usize,
    /// Source address of the connection initiator (SYN sender).
    initiator: Option<(IpAddr, u16)>,
    /// Next expected sequence number: initiator → responder.
    fwd_next_seq: Option<u32>,
    /// Next expected sequence number: responder → initiator.
    rev_next_seq: Option<u32>,
    /// Tick value when this stream was last active.
    last_active: u64,
}

impl StreamState {
    fn new() -> Self {
        StreamState {
            payload: Vec::new(),
            packets_seen: 0,
            finished: false,
            emitted_offset: 0,
            initiator: None,
            fwd_next_seq: None,
            rev_next_seq: None,
            last_active: 0,
        }
    }

    fn is_forward(&self, packet: &ParsedPacket) -> bool {
        match (self.initiator, packet.src_ip, packet.src_port) {
            (Some((init_ip, init_port)), Some(src_ip), Some(src_port)) => {
                init_ip == src_ip && init_port == src_port
            }
            _ => true,
        }
    }
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
            tick: 0,
        }
    }

    /// Process a TCP packet. Returns stream data when the stream has new payload
    /// to match against (on PSH or when the stream closes via FIN/RST).
    /// Only emits data that hasn't been emitted before (incremental).
    pub fn process(&mut self, packet: &ParsedPacket) -> Option<StreamData> {
        self.tick += 1;
        let key = packet.stream_key()?;
        let flags = packet.tcp_flags?;

        // RST — tear down and emit any unemitted data
        if flags.rst {
            return self.streams.remove(&key).and_then(|state| {
                let unemitted = &state.payload[state.emitted_offset..];
                if unemitted.is_empty() {
                    None
                } else {
                    Some(StreamData {
                        key,
                        payload: unemitted.to_vec(),
                    })
                }
            });
        }

        // SYN without ACK — new connection
        if flags.syn && !flags.ack {
            self.evict_if_full();
            let mut state = StreamState::new();
            state.last_active = self.tick;
            if let (Some(ip), Some(port)) = (packet.src_ip, packet.src_port) {
                state.initiator = Some((ip, port));
            }
            // SYN consumes one sequence number
            state.fwd_next_seq = packet.seq.map(|s| s.wrapping_add(1));
            self.streams.insert(key, state);
            return None;
        }

        // SYN+ACK — record responder's initial sequence number
        if flags.syn && flags.ack {
            if let Some(state) = self.streams.get_mut(&key) {
                state.last_active = self.tick;
                state.rev_next_seq = packet.seq.map(|s| s.wrapping_add(1));
            }
            return None;
        }

        // Evict least-recently-active stream if at capacity for a new stream
        if !self.streams.contains_key(&key) {
            self.evict_if_full();
        }

        let state = self
            .streams
            .entry(key.clone())
            .or_insert_with(StreamState::new);
        state.last_active = self.tick;

        // Append payload with sequence-number-based deduplication
        if !packet.payload.is_empty() && state.payload.len() < self.max_stream_bytes {
            let is_fwd = state.is_forward(packet);
            let next_seq = if is_fwd {
                &mut state.fwd_next_seq
            } else {
                &mut state.rev_next_seq
            };

            let new_bytes = if let Some(seq) = packet.seq {
                match *next_seq {
                    Some(expected) => deduplicate(seq, &packet.payload, expected),
                    None => {
                        // First data packet for this direction — accept all,
                        // initialize tracking
                        *next_seq = Some(seq.wrapping_add(packet.payload.len() as u32));
                        &packet.payload[..]
                    }
                }
            } else {
                // No sequence number (shouldn't happen for TCP)
                &packet.payload[..]
            };

            // Update next_seq for cases handled by deduplicate()
            if let (Some(seq), Some(expected)) = (packet.seq, next_seq.as_ref()) {
                let end = seq.wrapping_add(packet.payload.len() as u32);
                if !new_bytes.is_empty() && seq_after(end, *expected) {
                    *next_seq = Some(end);
                }
            }

            if !new_bytes.is_empty() {
                let remaining = self.max_stream_bytes - state.payload.len();
                let to_copy = new_bytes.len().min(remaining);
                state.payload.extend_from_slice(&new_bytes[..to_copy]);
            }
        }

        state.packets_seen += 1;

        // Emit on PSH (data ready) or FIN (closing)
        let should_emit = flags.psh || flags.fin;

        if flags.fin {
            state.finished = true;
        }

        if should_emit && state.payload.len() > state.emitted_offset {
            let new_data = state.payload[state.emitted_offset..].to_vec();
            state.emitted_offset = state.payload.len();

            let data = StreamData {
                key: key.clone(),
                payload: new_data,
            };

            if state.finished {
                self.streams.remove(&key);
            }

            Some(data)
        } else {
            None
        }
    }

    /// Evict the least-recently-active stream if at capacity.
    fn evict_if_full(&mut self) {
        if self.streams.len() < self.max_streams {
            return;
        }
        // Find the stream with the smallest last_active value
        let oldest_key = self
            .streams
            .iter()
            .min_by_key(|(_, state)| state.last_active)
            .map(|(key, _)| key.clone());
        if let Some(key) = oldest_key {
            self.streams.remove(&key);
        }
    }
}

/// Determine which bytes in `payload` are new based on sequence number tracking.
/// `seq` is the TCP sequence number of the first byte in `payload`.
/// `expected` is the next sequence number we expect for this direction.
///
/// Note: Out-of-order packets that arrive after a gap has been accepted will be
/// treated as retransmissions and dropped. True out-of-order reassembly would
/// require a reorder buffer, which is not implemented.
fn deduplicate<'a>(seq: u32, payload: &'a [u8], expected: u32) -> &'a [u8] {
    // How many bytes of this segment overlap with already-seen data?
    let overlap = expected.wrapping_sub(seq) as i32;

    if overlap <= 0 {
        // Packet starts at or after expected position (exact or gap) — all new
        payload
    } else if (overlap as usize) < payload.len() {
        // Partial retransmission — skip the already-seen prefix
        &payload[overlap as usize..]
    } else {
        // Full retransmission — nothing new
        &[]
    }
}

/// Returns true if `a` is strictly after `b` in TCP sequence space.
fn seq_after(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) > 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{TcpFlags, Transport};
    use std::net::Ipv4Addr;

    fn make_packet(
        src_port: u16,
        dst_port: u16,
        seq: u32,
        flags: TcpFlags,
        payload: &[u8],
    ) -> ParsedPacket {
        ParsedPacket {
            src_ip: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
            dst_ip: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))),
            src_port: Some(src_port),
            dst_port: Some(dst_port),
            transport: Transport::Tcp,
            payload: payload.to_vec(),
            tcp_flags: Some(flags),
            seq: Some(seq),
        }
    }

    fn syn() -> TcpFlags {
        TcpFlags {
            syn: true,
            ack: false,
            fin: false,
            rst: false,
            psh: false,
        }
    }

    fn syn_ack() -> TcpFlags {
        TcpFlags {
            syn: true,
            ack: true,
            fin: false,
            rst: false,
            psh: false,
        }
    }

    fn psh_ack() -> TcpFlags {
        TcpFlags {
            syn: false,
            ack: true,
            fin: false,
            rst: false,
            psh: true,
        }
    }

    fn fin_ack() -> TcpFlags {
        TcpFlags {
            syn: false,
            ack: true,
            fin: true,
            rst: false,
            psh: false,
        }
    }

    fn rst_flags() -> TcpFlags {
        TcpFlags {
            syn: false,
            ack: false,
            fin: false,
            rst: true,
            psh: false,
        }
    }

    #[test]
    fn basic_stream_reassembly() {
        let mut table = StreamTable::new();

        // SYN
        let pkt = make_packet(1234, 80, 100, syn(), &[]);
        assert!(table.process(&pkt).is_none());

        // SYN-ACK
        let pkt = make_packet(80, 1234, 200, syn_ack(), &[]);
        assert!(table.process(&pkt).is_none());

        // Data with PSH
        let pkt = make_packet(1234, 80, 101, psh_ack(), b"hello");
        let data = table.process(&pkt).unwrap();
        assert_eq!(data.payload, b"hello");
    }

    #[test]
    fn incremental_emission() {
        let mut table = StreamTable::new();

        let pkt = make_packet(1234, 80, 100, syn(), &[]);
        table.process(&pkt);
        let pkt = make_packet(80, 1234, 200, syn_ack(), &[]);
        table.process(&pkt);

        // First data chunk
        let pkt = make_packet(1234, 80, 101, psh_ack(), b"hello ");
        let data = table.process(&pkt).unwrap();
        assert_eq!(data.payload, b"hello ");

        // Second data chunk — should only contain NEW data
        let pkt = make_packet(1234, 80, 107, psh_ack(), b"world");
        let data = table.process(&pkt).unwrap();
        assert_eq!(data.payload, b"world");
    }

    #[test]
    fn retransmission_dedup() {
        let mut table = StreamTable::new();

        let pkt = make_packet(1234, 80, 100, syn(), &[]);
        table.process(&pkt);
        let pkt = make_packet(80, 1234, 200, syn_ack(), &[]);
        table.process(&pkt);

        // Original data
        let pkt = make_packet(1234, 80, 101, psh_ack(), b"hello");
        let data = table.process(&pkt).unwrap();
        assert_eq!(data.payload, b"hello");

        // Retransmit of same data — should emit nothing
        let pkt = make_packet(1234, 80, 101, psh_ack(), b"hello");
        assert!(table.process(&pkt).is_none());
    }

    #[test]
    fn partial_retransmission() {
        let mut table = StreamTable::new();

        let pkt = make_packet(1234, 80, 100, syn(), &[]);
        table.process(&pkt);
        let pkt = make_packet(80, 1234, 200, syn_ack(), &[]);
        table.process(&pkt);

        // Original: seq=101, len=5 ("hello"), next_seq becomes 106
        let pkt = make_packet(1234, 80, 101, psh_ack(), b"hello");
        table.process(&pkt);

        // Partial retransmit: seq=104, len=5 ("lo wo"), overlaps 2 bytes
        let pkt = make_packet(1234, 80, 104, psh_ack(), b"lo wo");
        let data = table.process(&pkt).unwrap();
        // Only the new bytes after expected seq 106
        assert_eq!(data.payload, b" wo");
    }

    #[test]
    fn rst_emits_unemitted() {
        let mut table = StreamTable::new();

        let pkt = make_packet(1234, 80, 100, syn(), &[]);
        table.process(&pkt);
        let pkt = make_packet(80, 1234, 200, syn_ack(), &[]);
        table.process(&pkt);

        // Data without PSH — buffered, not emitted
        let ack = TcpFlags {
            syn: false,
            ack: true,
            fin: false,
            rst: false,
            psh: false,
        };
        let pkt = make_packet(1234, 80, 101, ack, b"buffered");
        assert!(table.process(&pkt).is_none());

        // RST — should emit the buffered data
        let pkt = make_packet(1234, 80, 109, rst_flags(), &[]);
        let data = table.process(&pkt).unwrap();
        assert_eq!(data.payload, b"buffered");
    }

    #[test]
    fn fin_emits_and_removes() {
        let mut table = StreamTable::new();

        let pkt = make_packet(1234, 80, 100, syn(), &[]);
        table.process(&pkt);
        let pkt = make_packet(80, 1234, 200, syn_ack(), &[]);
        table.process(&pkt);

        let pkt = make_packet(1234, 80, 101, fin_ack(), b"bye");
        let data = table.process(&pkt).unwrap();
        assert_eq!(data.payload, b"bye");

        // Stream should be removed after FIN
        assert!(table.streams.is_empty());
    }

    #[test]
    fn bidirectional_data() {
        let mut table = StreamTable::new();

        // Client SYN
        let pkt = make_packet(1234, 80, 100, syn(), &[]);
        table.process(&pkt);
        // Server SYN-ACK
        let pkt = make_packet(80, 1234, 200, syn_ack(), &[]);
        table.process(&pkt);

        // Client sends request
        let pkt = make_packet(1234, 80, 101, psh_ack(), b"GET / ");
        let data = table.process(&pkt).unwrap();
        assert_eq!(data.payload, b"GET / ");

        // Server sends response
        let pkt = make_packet(80, 1234, 201, psh_ack(), b"HTTP/1.1 200 OK");
        let data = table.process(&pkt).unwrap();
        assert_eq!(data.payload, b"HTTP/1.1 200 OK");
    }

    #[test]
    fn evict_oldest_stream_at_capacity() {
        let mut table = StreamTable::new();
        table.max_streams = 3; // small limit for testing

        // Create 3 streams with SYNs (ports 1, 2, 3)
        for i in 1..=3u16 {
            let pkt = make_packet(i * 1000, 80, 100, syn(), &[]);
            table.process(&pkt);
        }
        assert_eq!(table.streams.len(), 3);

        // Add a 4th stream — should evict the oldest (port 1000, tick=1)
        let pkt = make_packet(4000, 80, 100, syn(), &[]);
        table.process(&pkt);
        assert_eq!(table.streams.len(), 3);

        // Stream with port 1000 should be gone
        let key_1000 = StreamKey::new(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            1000,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            80,
        );
        assert!(!table.streams.contains_key(&key_1000));

        // Stream with port 4000 should exist
        let key_4000 = StreamKey::new(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            4000,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            80,
        );
        assert!(table.streams.contains_key(&key_4000));
    }

    #[test]
    fn evict_respects_last_active() {
        let mut table = StreamTable::new();
        table.max_streams = 2;

        // Create stream A (port 1000)
        let pkt = make_packet(1000, 80, 100, syn(), &[]);
        table.process(&pkt);

        // Create stream B (port 2000)
        let pkt = make_packet(2000, 80, 100, syn(), &[]);
        table.process(&pkt);

        // Touch stream A again with more data (updates last_active)
        let pkt = make_packet(1000, 80, 101, psh_ack(), b"data");
        table.process(&pkt);

        // Add stream C — should evict B (older last_active), not A
        let pkt = make_packet(3000, 80, 100, syn(), &[]);
        table.process(&pkt);

        let key_a = StreamKey::new(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            1000,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            80,
        );
        let key_b = StreamKey::new(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            2000,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            80,
        );
        assert!(table.streams.contains_key(&key_a)); // A was touched, survives
        assert!(!table.streams.contains_key(&key_b)); // B was evicted
    }

    #[test]
    fn deduplicate_unit() {
        // Exact match
        assert_eq!(deduplicate(100, b"hello", 100), b"hello");
        // Gap (packet after expected)
        assert_eq!(deduplicate(110, b"world", 100), b"world");
        // Full retransmit
        assert_eq!(deduplicate(90, b"old", 100), b"");
        // Partial retransmit: expected=100, seq=95, len=10 => bytes 5..10 are new
        assert_eq!(deduplicate(95, b"0123456789", 100), b"56789");
    }
}
