use std::collections::{BTreeMap, HashMap};
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

/// Direction of a stream emission.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    Forward,
    Reverse,
}

/// Per-direction buffer for ordered reassembly with reorder support.
struct DirectionBuffer {
    /// In-order payload accumulated so far.
    payload: Vec<u8>,
    /// Next expected sequence number.
    next_seq: Option<u32>,
    /// Out-of-order segments buffered for reordering, keyed by seq number.
    reorder_buf: BTreeMap<u32, Vec<u8>>,
    /// Byte offset up to which we've already emitted data.
    emitted_offset: usize,
}

impl DirectionBuffer {
    fn new() -> Self {
        DirectionBuffer {
            payload: Vec::new(),
            next_seq: None,
            reorder_buf: BTreeMap::new(),
            emitted_offset: 0,
        }
    }

    /// Append new data, using the reorder buffer to handle out-of-order segments.
    /// Returns true if any new in-order bytes were added.
    fn append(&mut self, seq: u32, data: &[u8], max_bytes: usize) -> bool {
        if data.is_empty() {
            return false;
        }

        match self.next_seq {
            None => {
                // First data for this direction
                let to_copy = data.len().min(max_bytes.saturating_sub(self.payload.len()));
                if to_copy > 0 {
                    self.payload.extend_from_slice(&data[..to_copy]);
                }
                self.next_seq = Some(seq.wrapping_add(data.len() as u32));
                true
            }
            Some(expected) => {
                let diff = seq.wrapping_sub(expected) as i32;

                if diff == 0 {
                    // Exact match — append directly
                    let to_copy = data.len().min(max_bytes.saturating_sub(self.payload.len()));
                    if to_copy > 0 {
                        self.payload.extend_from_slice(&data[..to_copy]);
                    }
                    self.next_seq = Some(seq.wrapping_add(data.len() as u32));
                    // Flush any buffered segments that are now in order
                    self.flush_reorder_buf(max_bytes);
                    true
                } else if diff > 0 {
                    // Gap — buffer for reordering (limit count and bytes)
                    if self.reorder_buf.len() < MAX_REORDER_SEGMENTS {
                        let reorder_bytes: usize = self.reorder_buf.values().map(|v| v.len()).sum();
                        if self.payload.len() + reorder_bytes + data.len() <= max_bytes {
                            self.reorder_buf.insert(seq, data.to_vec());
                        }
                    }
                    false
                } else {
                    // Overlap/retransmission
                    let overlap = (-diff) as usize;
                    if overlap < data.len() {
                        let new_data = &data[overlap..];
                        let to_copy = new_data
                            .len()
                            .min(max_bytes.saturating_sub(self.payload.len()));
                        if to_copy > 0 {
                            self.payload.extend_from_slice(&new_data[..to_copy]);
                        }
                        let end = seq.wrapping_add(data.len() as u32);
                        if seq_after(end, expected) {
                            self.next_seq = Some(end);
                        }
                        // Flush any buffered segments that are now in order
                        self.flush_reorder_buf(max_bytes);
                        to_copy > 0
                    } else {
                        // Full retransmission — nothing new
                        false
                    }
                }
            }
        }
    }

    /// Drain reorder buffer for segments that are now in order.
    fn flush_reorder_buf(&mut self, max_bytes: usize) {
        while let Some(expected) = self.next_seq {
            // Try direct lookup first — handles seq wrapping correctly since
            // BTreeMap ordering can break at the u32 boundary, but exact key
            // lookup always works.
            if let Some(seg_data) = self.reorder_buf.remove(&expected) {
                let to_copy = seg_data
                    .len()
                    .min(max_bytes.saturating_sub(self.payload.len()));
                if to_copy > 0 {
                    self.payload.extend_from_slice(&seg_data[..to_copy]);
                }
                self.next_seq = Some(expected.wrapping_add(seg_data.len() as u32));
                continue;
            }

            // Fallback: check the first entry for overlap with expected
            let next_entry = self.reorder_buf.iter().next().map(|(k, _)| *k);
            match next_entry {
                Some(seg_seq) => {
                    let diff = seg_seq.wrapping_sub(expected) as i32;
                    if diff > 0 {
                        // Still a gap — stop flushing
                        break;
                    }
                    let seg_data = self.reorder_buf.remove(&seg_seq).unwrap();
                    // Overlap
                    let overlap = (-diff) as usize;
                    if overlap < seg_data.len() {
                        let new_data = &seg_data[overlap..];
                        let to_copy = new_data
                            .len()
                            .min(max_bytes.saturating_sub(self.payload.len()));
                        if to_copy > 0 {
                            self.payload.extend_from_slice(&new_data[..to_copy]);
                        }
                        let end = seg_seq.wrapping_add(seg_data.len() as u32);
                        if seq_after(end, expected) {
                            self.next_seq = Some(end);
                        }
                    }
                    // Full retransmission — discard and continue
                }
                None => break,
            }
        }
    }

    /// Return new bytes since last emission, if any.
    fn drain_new(&mut self) -> Option<Vec<u8>> {
        if self.payload.len() > self.emitted_offset {
            let new_data = self.payload[self.emitted_offset..].to_vec();
            self.emitted_offset = self.payload.len();
            Some(new_data)
        } else {
            None
        }
    }

    /// Return all unemitted bytes (for RST/final drain).
    fn drain_all(&self) -> Option<Vec<u8>> {
        let unemitted = &self.payload[self.emitted_offset..];
        if unemitted.is_empty() {
            None
        } else {
            Some(unemitted.to_vec())
        }
    }

    fn total_bytes(&self) -> usize {
        self.payload.len()
    }
}

/// Maximum out-of-order segments to buffer per direction.
const MAX_REORDER_SEGMENTS: usize = 32;

struct StreamState {
    fwd: DirectionBuffer,
    rev: DirectionBuffer,
    /// Track per-direction FIN: [fwd_fin, rev_fin].
    fin_seen: [bool; 2],
    /// Source address of the connection initiator (SYN sender).
    initiator: Option<(IpAddr, u16)>,
    /// Tick value when this stream was last active.
    last_active: u64,
}

impl StreamState {
    fn new() -> Self {
        StreamState {
            fwd: DirectionBuffer::new(),
            rev: DirectionBuffer::new(),
            fin_seen: [false, false],
            initiator: None,
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

    fn both_fins(&self) -> bool {
        self.fin_seen[0] && self.fin_seen[1]
    }
}

/// Reassembled stream data emitted when a stream has enough data to match against.
pub struct StreamData {
    pub key: StreamKey,
    pub payload: Vec<u8>,
    pub direction: Direction,
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
            max_stream_bytes: 262_144, // 256 KB per stream per direction
            tick: 0,
        }
    }

    /// Process a TCP packet. Returns stream data when the stream has new payload
    /// to match against (on PSH or when the stream closes via FIN/RST).
    /// RST emits both directions (forward and reverse) if they have unemitted data.
    pub fn process(&mut self, packet: &ParsedPacket) -> Vec<StreamData> {
        self.tick += 1;

        // M17: Periodically sweep stale streams to prevent memory leaks
        // from connections that never close cleanly.
        if self.tick % 10_000 == 0 {
            self.sweep_stale();
        }
        let key = match packet.stream_key() {
            Some(k) => k,
            None => return vec![],
        };
        let flags = match packet.tcp_flags {
            Some(f) => f,
            None => return vec![],
        };

        // RST — tear down and emit any unemitted data from both directions
        if flags.rst {
            if let Some(state) = self.streams.remove(&key) {
                let mut results = Vec::new();
                if let Some(p) = state.fwd.drain_all() {
                    results.push(StreamData {
                        key: key.clone(),
                        payload: p,
                        direction: Direction::Forward,
                    });
                }
                if let Some(p) = state.rev.drain_all() {
                    results.push(StreamData {
                        key,
                        payload: p,
                        direction: Direction::Reverse,
                    });
                }
                return results;
            }
            return vec![];
        }

        // SYN without ACK — new connection (emit old stream data if key exists)
        if flags.syn && !flags.ack {
            let mut results = Vec::new();
            // If a stream already exists for this key, emit its data first
            if let Some(old_state) = self.streams.remove(&key) {
                if let Some(p) = old_state.fwd.drain_all() {
                    results.push(StreamData {
                        key: key.clone(),
                        payload: p,
                        direction: Direction::Forward,
                    });
                }
                if let Some(p) = old_state.rev.drain_all() {
                    results.push(StreamData {
                        key: key.clone(),
                        payload: p,
                        direction: Direction::Reverse,
                    });
                }
            }
            self.evict_if_full();
            let mut state = StreamState::new();
            state.last_active = self.tick;
            if let (Some(ip), Some(port)) = (packet.src_ip, packet.src_port) {
                state.initiator = Some((ip, port));
            }
            // SYN consumes one sequence number
            state.fwd.next_seq = packet.seq.map(|s| s.wrapping_add(1));
            self.streams.insert(key, state);
            return results;
        }

        // SYN+ACK — record responder's initial sequence number
        if flags.syn && flags.ack {
            if let Some(state) = self.streams.get_mut(&key) {
                state.last_active = self.tick;
                state.rev.next_seq = packet.seq.map(|s| s.wrapping_add(1));
            }
            return vec![];
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

        // Set initiator from first data packet if not yet known (H6)
        if state.initiator.is_none()
            && !packet.payload.is_empty()
            && let (Some(ip), Some(port)) = (packet.src_ip, packet.src_port)
        {
            state.initiator = Some((ip, port));
        }

        let is_fwd = state.is_forward(packet);
        let dir = if is_fwd {
            Direction::Forward
        } else {
            Direction::Reverse
        };

        // Append payload with sequence-number-based deduplication + reordering
        if !packet.payload.is_empty() {
            let buf = if is_fwd {
                &mut state.fwd
            } else {
                &mut state.rev
            };
            let max = self.max_stream_bytes;

            // Count reorder buffer bytes against max_stream_bytes (M15)
            let reorder_bytes: usize = buf.reorder_buf.values().map(|v| v.len()).sum();
            let effective_total = buf.total_bytes() + reorder_bytes;

            if effective_total < max {
                if let Some(seq) = packet.seq {
                    buf.append(seq, &packet.payload, max);
                } else {
                    // No sequence number (shouldn't happen for TCP) — append raw
                    let remaining = max.saturating_sub(buf.payload.len());
                    let to_copy = packet.payload.len().min(remaining);
                    if to_copy > 0 {
                        buf.payload.extend_from_slice(&packet.payload[..to_copy]);
                    }
                }
            }
        }

        // Track per-direction FIN
        if flags.fin {
            if is_fwd {
                state.fin_seen[0] = true;
            } else {
                state.fin_seen[1] = true;
            }
        }

        // Emit on PSH (data ready) or FIN (closing)
        let should_emit = flags.psh || flags.fin;

        if should_emit {
            let buf = if is_fwd {
                &mut state.fwd
            } else {
                &mut state.rev
            };
            let result = buf.drain_new().map(|payload| StreamData {
                key: key.clone(),
                payload,
                direction: dir,
            });

            // Remove stream only when both directions have FIN'd
            if state.both_fins() {
                self.streams.remove(&key);
            }

            match result {
                Some(sd) => vec![sd],
                None => vec![],
            }
        } else {
            vec![]
        }
    }

    /// M17: Remove streams that haven't been active for a long time.
    /// Called periodically (every 10k ticks) to prevent memory leaks.
    fn sweep_stale(&mut self) {
        const STALE_THRESHOLD: u64 = 100_000;
        let current_tick = self.tick;
        self.streams
            .retain(|_, state| current_tick.saturating_sub(state.last_active) < STALE_THRESHOLD);
    }

    /// Evict the least-recently-active stream if at capacity.
    /// M16: This is O(n) over all streams. Acceptable because max_streams
    /// defaults to 10,000 and eviction is rare (only when at capacity).
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
            vlan_id: None,
            icmp_type: None,
            icmp_code: None,
            timestamp: None,
        }
    }

    /// Make a packet in the reverse direction (server → client).
    fn make_reverse_packet(
        src_port: u16,
        dst_port: u16,
        seq: u32,
        flags: TcpFlags,
        payload: &[u8],
    ) -> ParsedPacket {
        ParsedPacket {
            src_ip: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))),
            dst_ip: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
            src_port: Some(src_port),
            dst_port: Some(dst_port),
            transport: Transport::Tcp,
            payload: payload.to_vec(),
            tcp_flags: Some(flags),
            seq: Some(seq),
            vlan_id: None,
            icmp_type: None,
            icmp_code: None,
            timestamp: None,
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

    fn ack_only() -> TcpFlags {
        TcpFlags {
            syn: false,
            ack: true,
            fin: false,
            rst: false,
            psh: false,
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

    /// Helper: process and expect exactly one StreamData result.
    fn process_one(table: &mut StreamTable, pkt: &ParsedPacket) -> StreamData {
        let mut results = table.process(pkt);
        assert_eq!(
            results.len(),
            1,
            "expected exactly 1 result, got {}",
            results.len()
        );
        results.remove(0)
    }

    #[test]
    fn basic_stream_reassembly() {
        let mut table = StreamTable::new();

        // SYN
        let pkt = make_packet(1234, 80, 100, syn(), &[]);
        assert!(table.process(&pkt).is_empty());

        // SYN-ACK (from server)
        let pkt = make_reverse_packet(80, 1234, 200, syn_ack(), &[]);
        assert!(table.process(&pkt).is_empty());

        // Data with PSH
        let pkt = make_packet(1234, 80, 101, psh_ack(), b"hello");
        let data = process_one(&mut table, &pkt);
        assert_eq!(data.payload, b"hello");
        assert_eq!(data.direction, Direction::Forward);
    }

    #[test]
    fn incremental_emission() {
        let mut table = StreamTable::new();

        let pkt = make_packet(1234, 80, 100, syn(), &[]);
        table.process(&pkt);
        let pkt = make_reverse_packet(80, 1234, 200, syn_ack(), &[]);
        table.process(&pkt);

        // First data chunk
        let pkt = make_packet(1234, 80, 101, psh_ack(), b"hello ");
        let data = process_one(&mut table, &pkt);
        assert_eq!(data.payload, b"hello ");

        // Second data chunk — should only contain NEW data
        let pkt = make_packet(1234, 80, 107, psh_ack(), b"world");
        let data = process_one(&mut table, &pkt);
        assert_eq!(data.payload, b"world");
    }

    #[test]
    fn retransmission_dedup() {
        let mut table = StreamTable::new();

        let pkt = make_packet(1234, 80, 100, syn(), &[]);
        table.process(&pkt);
        let pkt = make_reverse_packet(80, 1234, 200, syn_ack(), &[]);
        table.process(&pkt);

        // Original data
        let pkt = make_packet(1234, 80, 101, psh_ack(), b"hello");
        let data = process_one(&mut table, &pkt);
        assert_eq!(data.payload, b"hello");

        // Retransmit of same data — should emit nothing
        let pkt = make_packet(1234, 80, 101, psh_ack(), b"hello");
        assert!(table.process(&pkt).is_empty());
    }

    #[test]
    fn partial_retransmission() {
        let mut table = StreamTable::new();

        let pkt = make_packet(1234, 80, 100, syn(), &[]);
        table.process(&pkt);
        let pkt = make_reverse_packet(80, 1234, 200, syn_ack(), &[]);
        table.process(&pkt);

        // Original: seq=101, len=5 ("hello"), next_seq becomes 106
        let pkt = make_packet(1234, 80, 101, psh_ack(), b"hello");
        table.process(&pkt);

        // Partial retransmit: seq=104, len=5 ("lo wo"), overlaps 2 bytes
        let pkt = make_packet(1234, 80, 104, psh_ack(), b"lo wo");
        let data = process_one(&mut table, &pkt);
        // Only the new bytes after expected seq 106
        assert_eq!(data.payload, b" wo");
    }

    #[test]
    fn rst_emits_both_directions() {
        let mut table = StreamTable::new();

        let pkt = make_packet(1234, 80, 100, syn(), &[]);
        table.process(&pkt);
        let pkt = make_reverse_packet(80, 1234, 200, syn_ack(), &[]);
        table.process(&pkt);

        // Data without PSH in both directions — buffered
        let pkt = make_packet(1234, 80, 101, ack_only(), b"client-data");
        assert!(table.process(&pkt).is_empty());
        let pkt = make_reverse_packet(80, 1234, 201, ack_only(), b"server-data");
        assert!(table.process(&pkt).is_empty());

        // RST — should emit both directions
        let pkt = make_packet(1234, 80, 112, rst_flags(), &[]);
        let results = table.process(&pkt);
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].payload, b"client-data");
        assert_eq!(results[0].direction, Direction::Forward);
        assert_eq!(results[1].payload, b"server-data");
        assert_eq!(results[1].direction, Direction::Reverse);
    }

    #[test]
    fn rst_emits_unemitted() {
        let mut table = StreamTable::new();

        let pkt = make_packet(1234, 80, 100, syn(), &[]);
        table.process(&pkt);
        let pkt = make_reverse_packet(80, 1234, 200, syn_ack(), &[]);
        table.process(&pkt);

        // Data without PSH — buffered, not emitted
        let pkt = make_packet(1234, 80, 101, ack_only(), b"buffered");
        assert!(table.process(&pkt).is_empty());

        // RST — should emit the buffered data
        let pkt = make_packet(1234, 80, 109, rst_flags(), &[]);
        let results = table.process(&pkt);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].payload, b"buffered");
    }

    #[test]
    fn fin_per_direction() {
        let mut table = StreamTable::new();

        let pkt = make_packet(1234, 80, 100, syn(), &[]);
        table.process(&pkt);
        let pkt = make_reverse_packet(80, 1234, 200, syn_ack(), &[]);
        table.process(&pkt);

        // Client sends data + FIN
        let pkt = make_packet(1234, 80, 101, fin_ack(), b"bye");
        let data = process_one(&mut table, &pkt);
        assert_eq!(data.payload, b"bye");

        // Stream should still exist (only one FIN)
        let key = StreamKey::new(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            1234,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            80,
        );
        assert!(table.streams.contains_key(&key));

        // Server sends FIN — now stream is removed
        let pkt = make_reverse_packet(80, 1234, 201, fin_ack(), &[]);
        table.process(&pkt);
        assert!(!table.streams.contains_key(&key));
    }

    #[test]
    fn bidirectional_data_separate() {
        let mut table = StreamTable::new();

        // Client SYN
        let pkt = make_packet(1234, 80, 100, syn(), &[]);
        table.process(&pkt);
        // Server SYN-ACK
        let pkt = make_reverse_packet(80, 1234, 200, syn_ack(), &[]);
        table.process(&pkt);

        // Client sends request
        let pkt = make_packet(1234, 80, 101, psh_ack(), b"GET / ");
        let data = process_one(&mut table, &pkt);
        assert_eq!(data.payload, b"GET / ");
        assert_eq!(data.direction, Direction::Forward);

        // Server sends response — separate buffer
        let pkt = make_reverse_packet(80, 1234, 201, psh_ack(), b"HTTP/1.1 200 OK");
        let data = process_one(&mut table, &pkt);
        assert_eq!(data.payload, b"HTTP/1.1 200 OK");
        assert_eq!(data.direction, Direction::Reverse);
    }

    #[test]
    fn out_of_order_reassembly() {
        let mut table = StreamTable::new();

        let pkt = make_packet(1234, 80, 100, syn(), &[]);
        table.process(&pkt);
        let pkt = make_reverse_packet(80, 1234, 200, syn_ack(), &[]);
        table.process(&pkt);

        // Packet B arrives first (seq=106, "world")
        let pkt = make_packet(1234, 80, 106, ack_only(), b"world");
        assert!(table.process(&pkt).is_empty()); // buffered

        // Packet A arrives (seq=101, "hello"), fills the gap
        let pkt = make_packet(1234, 80, 101, psh_ack(), b"hello");
        let data = process_one(&mut table, &pkt);
        // Both packets should be in order
        assert_eq!(data.payload, b"helloworld");
    }

    #[test]
    fn out_of_order_multiple_gaps() {
        let mut table = StreamTable::new();

        let pkt = make_packet(1234, 80, 100, syn(), &[]);
        table.process(&pkt);
        let pkt = make_reverse_packet(80, 1234, 200, syn_ack(), &[]);
        table.process(&pkt);

        // Send segments 3, 1, 2 out of order
        // Segment 3: seq=111, "ccc"
        let pkt = make_packet(1234, 80, 111, ack_only(), b"ccc");
        assert!(table.process(&pkt).is_empty());

        // Segment 1: seq=101, "aaaaa" — fills gap partially
        let pkt = make_packet(1234, 80, 101, ack_only(), b"aaaaa");
        assert!(table.process(&pkt).is_empty()); // no PSH, not emitted yet

        // Segment 2: seq=106, "bbbbb" — fills remaining gap, flushes segment 3 too
        let pkt = make_packet(1234, 80, 106, psh_ack(), b"bbbbb");
        let data = process_one(&mut table, &pkt);
        assert_eq!(data.payload, b"aaaaabbbbbccc");
    }

    #[test]
    fn syn_on_existing_stream_emits_old_data() {
        let mut table = StreamTable::new();

        // First connection
        let pkt = make_packet(1234, 80, 100, syn(), &[]);
        table.process(&pkt);
        let pkt = make_reverse_packet(80, 1234, 200, syn_ack(), &[]);
        table.process(&pkt);
        let pkt = make_packet(1234, 80, 101, ack_only(), b"old-data");
        table.process(&pkt);

        // New SYN on same key — should emit old stream's data
        let pkt = make_packet(1234, 80, 500, syn(), &[]);
        let results = table.process(&pkt);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].payload, b"old-data");
    }

    #[test]
    fn initiator_detected_from_first_data_packet() {
        let mut table = StreamTable::new();

        // Data packet arrives without prior SYN (mid-stream join)
        let pkt = make_packet(1234, 80, 100, psh_ack(), b"request");
        let results = table.process(&pkt);
        assert_eq!(results.len(), 1);

        // Now a packet from the other direction should be detected as reverse
        let pkt = make_reverse_packet(80, 1234, 200, psh_ack(), b"response");
        let data = process_one(&mut table, &pkt);
        assert_eq!(data.direction, Direction::Reverse);
    }

    #[test]
    fn seq_after_wrapping() {
        // Test seq_after at u32 boundary
        assert!(seq_after(0, u32::MAX)); // 0 is after MAX in TCP seq space
        assert!(!seq_after(u32::MAX, 0));
        assert!(seq_after(1, 0));
        assert!(!seq_after(0, 1));
        // Same value is not "after"
        assert!(!seq_after(100, 100));
    }

    #[test]
    fn reorder_buffer_respects_byte_limit() {
        let mut table = StreamTable::new();
        table.max_stream_bytes = 20; // very small limit

        let pkt = make_packet(1234, 80, 100, syn(), &[]);
        table.process(&pkt);
        let pkt = make_reverse_packet(80, 1234, 200, syn_ack(), &[]);
        table.process(&pkt);

        // Fill in-order buffer with 15 bytes
        let pkt = make_packet(1234, 80, 101, ack_only(), b"123456789012345");
        table.process(&pkt);

        // Try to add 10 out-of-order bytes — would exceed limit
        let pkt = make_packet(1234, 80, 126, ack_only(), b"xxxxxxxxxx");
        table.process(&pkt);

        // The reorder buffer should have been skipped due to limit
        let key = StreamKey::new(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            1234,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            80,
        );
        let state = table.streams.get(&key).unwrap();
        // In-order data is 15 bytes, reorder_buf would push total over 20
        assert!(
            state.fwd.payload.len()
                + state
                    .fwd
                    .reorder_buf
                    .values()
                    .map(|v| v.len())
                    .sum::<usize>()
                <= 20
        );
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
        // Test via DirectionBuffer
        let mut buf = DirectionBuffer::new();
        assert!(buf.append(100, b"hello", 1024));
        assert_eq!(buf.payload, b"hello");

        // Gap
        assert!(!buf.append(110, b"world", 1024)); // buffered, not appended in-order
        // Exact continuation would be 105
        assert!(buf.append(105, b"XXXXX", 1024)); // fills gap, flushes "world"
        assert_eq!(buf.payload, b"helloXXXXXworld");

        // Full retransmit
        assert!(!buf.append(100, b"hello", 1024));
        assert_eq!(buf.payload, b"helloXXXXXworld"); // unchanged

        // Partial retransmit: seq 113 overlaps 2 bytes (next_seq=115), new data starts at "d"
        assert!(buf.append(113, b"rldNEW", 1024));
        assert_eq!(buf.payload, b"helloXXXXXworlddNEW");
    }
}
