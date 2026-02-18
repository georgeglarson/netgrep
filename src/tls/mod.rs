pub mod decrypt;
pub(crate) mod handshake;
pub mod keylog;

use std::collections::HashMap;
use std::net::IpAddr;

use ring::aead;
use ring::hkdf;
use tls_parser::*;

use zeroize::Zeroize;

use crate::protocol::StreamKey;
use decrypt::DirectionKeys;
use keylog::KeyLog;

/// Maximum accumulated handshake message size (64 KB — covers even post-quantum ClientHello).
const MAX_HANDSHAKE_BUF: usize = 65536;

/// Per-connection TLS state tracker.
struct TlsConnection {
    client_random: Option<[u8; 32]>,
    server_random: Option<[u8; 32]>,
    cipher_suite: Option<TlsCipherSuiteID>,
    version: Option<TlsVersion>,
    /// Application traffic keys.
    client_keys: Option<DirectionKeys>,
    server_keys: Option<DirectionKeys>,
    /// TLS 1.3 handshake traffic keys (used before Finished).
    client_hs_keys: Option<DirectionKeys>,
    server_hs_keys: Option<DirectionKeys>,
    /// Which endpoint is the client (sender of ClientHello).
    client_addr: Option<(IpAddr, u16)>,
    /// Per-direction raw TLS record buffers.
    from_client_buf: Vec<u8>,
    from_server_buf: Vec<u8>,
    /// Whether ChangeCipherSpec has been seen per direction (TLS 1.2).
    client_cipher_active: bool,
    server_cipher_active: bool,
    /// Accumulated decrypted plaintext from both directions.
    /// L3: Cleared atomically via std::mem::take in get_decrypted().
    decrypted: Vec<u8>,
    /// Monotonic tick updated on each packet for LRU eviction.
    last_active: u64,
    /// IV length from cipher suite (4 for AES-GCM, 12 for ChaCha20/TLS 1.3).
    iv_len: usize,
    /// M8: Per-direction handshake message reassembly buffer for messages
    /// spanning multiple TLS records. Keyed by direction (true = from_client).
    handshake_buf_client: Vec<u8>,
    handshake_buf_server: Vec<u8>,
    /// M10: Tracks whether the TLS 1.3 handshake phase is complete per direction.
    /// Once true, only application keys are tried (no dual-try fallback).
    client_hs_complete: bool,
    server_hs_complete: bool,
}

impl TlsConnection {
    fn new() -> Self {
        TlsConnection {
            client_random: None,
            server_random: None,
            cipher_suite: None,
            version: None,
            client_keys: None,
            server_keys: None,
            client_hs_keys: None,
            server_hs_keys: None,
            client_addr: None,
            from_client_buf: Vec::new(),
            from_server_buf: Vec::new(),
            client_cipher_active: false,
            server_cipher_active: false,
            decrypted: Vec::new(),
            last_active: 0,
            iv_len: 4,
            handshake_buf_client: Vec::new(),
            handshake_buf_server: Vec::new(),
            client_hs_complete: false,
            server_hs_complete: false,
        }
    }

    fn is_from_client(&self, src_ip: IpAddr, src_port: u16) -> bool {
        match self.client_addr {
            Some((ip, port)) => ip == src_ip && port == src_port,
            // Before ClientHello is seen, treat first sender as client
            None => true,
        }
    }
}

impl Drop for TlsConnection {
    fn drop(&mut self) {
        // M3: Zeroize sensitive buffers that may contain TLS record data
        self.from_client_buf.zeroize();
        self.from_server_buf.zeroize();
        self.decrypted.zeroize();
        self.handshake_buf_client.zeroize();
        self.handshake_buf_server.zeroize();
        // L4: Zeroize client_random/server_random (used to look up master secrets)
        if let Some(ref mut cr) = self.client_random {
            cr.zeroize();
        }
        if let Some(ref mut sr) = self.server_random {
            sr.zeroize();
        }
    }
}

// 5,000 connections * ~1.6 MB (buffers + decrypted + handshake) = ~8 GB worst case
const MAX_CONNECTIONS: usize = 5_000;
const MAX_DECRYPTED_BYTES: usize = 1_048_576; // 1 MB per connection
const MAX_BUFFER_BYTES: usize = 262_144; // 256 KB per direction buffer

/// Manages TLS decryption across all connections.
pub struct TlsDecryptor {
    keylog: KeyLog,
    connections: HashMap<StreamKey, TlsConnection>,
    tick: u64,
}

impl TlsDecryptor {
    pub fn new(keylog: KeyLog) -> Self {
        TlsDecryptor {
            keylog,
            connections: HashMap::new(),
            tick: 0,
        }
    }

    /// Process a single TCP packet's payload incrementally.
    /// Call this for every TCP packet, before stream reassembly.
    pub fn process_packet(
        &mut self,
        key: &StreamKey,
        payload: &[u8],
        src_ip: IpAddr,
        src_port: u16,
    ) {
        if payload.is_empty() {
            return;
        }

        self.tick = self.tick.saturating_add(1);

        // Evict least-recently-active connection if at capacity for a new one
        if !self.connections.contains_key(key) && self.connections.len() >= MAX_CONNECTIONS {
            self.evict_oldest();
        }

        let conn = self
            .connections
            .entry(key.clone())
            .or_insert_with(TlsConnection::new);
        conn.last_active = self.tick;
        let from_client = conn.is_from_client(src_ip, src_port);

        // Check buffer size before extending. On overflow, remove the entire
        // connection — just clearing the buffer would leave the parser at a
        // mid-record position, causing all subsequent parsing to fail.
        let overflow = if from_client {
            conn.from_client_buf.len() + payload.len() > MAX_BUFFER_BYTES
        } else {
            conn.from_server_buf.len() + payload.len() > MAX_BUFFER_BYTES
        };
        if overflow {
            eprintln!(
                "Warning: TLS {} buffer overflow, removing connection",
                if from_client { "client" } else { "server" },
            );
            self.connections.remove(key);
            return;
        }
        if from_client {
            conn.from_client_buf.extend_from_slice(payload);
        } else {
            conn.from_server_buf.extend_from_slice(payload);
        }

        self.drain_buffer(key, from_client, src_ip, src_port);
    }

    /// Get new decrypted plaintext since the last call for a connection.
    /// Returns None if no new decrypted data is available.
    /// L3: Uses std::mem::take to atomically swap and clear the buffer,
    /// avoiding the previous offset tracking + drain pattern.
    pub fn get_decrypted(&mut self, key: &StreamKey) -> Option<Vec<u8>> {
        let conn = self.connections.get_mut(key)?;
        if conn.decrypted.is_empty() {
            None
        } else {
            Some(std::mem::take(&mut conn.decrypted))
        }
    }

    /// Remove a connection's TLS state, zeroizing key material.
    /// Called when the stream table removes a stream (FIN/RST/eviction)
    /// so sensitive key material doesn't linger until LRU eviction.
    pub fn remove_connection(&mut self, key: &StreamKey) {
        self.connections.remove(key);
    }

    /// Evict the least-recently-active connection.
    fn evict_oldest(&mut self) {
        let oldest_key = self
            .connections
            .iter()
            .min_by_key(|(_, conn)| conn.last_active)
            .map(|(key, _)| key.clone());
        if let Some(key) = oldest_key {
            self.connections.remove(&key);
        }
    }

    /// Parse complete TLS records from one direction's buffer.
    fn drain_buffer(&mut self, key: &StreamKey, from_client: bool, src_ip: IpAddr, src_port: u16) {
        // Take the buffer out to avoid borrow conflicts with self methods
        let conn = match self.connections.get_mut(key) {
            Some(c) => c,
            None => return,
        };
        let buffer = if from_client {
            std::mem::take(&mut conn.from_client_buf)
        } else {
            std::mem::take(&mut conn.from_server_buf)
        };

        let mut offset = 0;

        while offset < buffer.len() {
            let remaining = &buffer[offset..];

            // Need at least 5 bytes for a TLS record header
            if remaining.len() < 5 {
                break;
            }

            // L20: Validate record type byte (0x14-0x17: CCS, Alert, Handshake, AppData)
            let record_type = remaining[0];
            if !(0x14..=0x17).contains(&record_type) {
                // Not a TLS record — discard this direction's buffer
                offset = buffer.len();
                break;
            }

            // Validate TLS version field (bytes 1-2): SSL 3.0 through TLS 1.3
            let record_version = u16::from_be_bytes([remaining[1], remaining[2]]);
            if !(0x0300..=0x0304).contains(&record_version) {
                offset = buffer.len();
                break;
            }

            // Check if we have the complete record body
            let record_body_len = u16::from_be_bytes([remaining[3], remaining[4]]) as usize;

            // L21: Reject records with body > 16384 + 2048 (TLS max + overhead)
            if record_body_len > 16384 + 2048 {
                offset = buffer.len();
                break;
            }

            if remaining.len() < 5 + record_body_len {
                break; // Incomplete record, wait for more data
            }

            // Parse the complete record
            let (_, record) = match parse_tls_raw_record(remaining) {
                Ok(r) => r,
                Err(_) => {
                    offset = buffer.len();
                    break;
                }
            };

            // Check if cipher is active for this direction (TLS 1.2 post-CCS)
            let cipher_active = {
                let c = self.connections.get(key);
                c.map(|c| {
                    if from_client {
                        c.client_cipher_active
                    } else {
                        c.server_cipher_active
                    }
                })
                .unwrap_or(false)
            };

            match record.hdr.record_type {
                TlsRecordType::ChangeCipherSpec => {
                    self.try_derive_keys(key);
                    if let Some(conn) = self.connections.get_mut(key) {
                        if from_client {
                            conn.client_cipher_active = true;
                        } else {
                            conn.server_cipher_active = true;
                        }
                    }
                }
                TlsRecordType::Handshake if !cipher_active => {
                    // M8: Reassemble handshake messages across TLS records.
                    // The handshake message header is 4 bytes: type(1) + length(3).
                    // Accumulate data until we have the full message.
                    self.accumulate_handshake(key, record.data, from_client, src_ip, src_port);
                }
                // Encrypted Alert records must be decrypted to advance sequence
                // counters, otherwise all subsequent decryption fails (wrong nonce).
                TlsRecordType::Alert if cipher_active => {
                    if let Some(mut plaintext) = self.decrypt_record(key, &record, src_ip, src_port)
                    {
                        plaintext.zeroize();
                    }
                }
                // After CCS, handshake records (Finished) are encrypted — decrypt to advance seq
                TlsRecordType::Handshake | TlsRecordType::ApplicationData => {
                    if let Some(mut plaintext) = self.decrypt_record(key, &record, src_ip, src_port)
                    {
                        if record.hdr.record_type == TlsRecordType::ApplicationData {
                            if let Some(conn) = self.connections.get_mut(key) {
                                let remaining =
                                    MAX_DECRYPTED_BYTES.saturating_sub(conn.decrypted.len());
                                let to_copy = plaintext.len().min(remaining);
                                if to_copy > 0 {
                                    conn.decrypted.extend_from_slice(&plaintext[..to_copy]);
                                }
                            }
                        }
                        plaintext.zeroize();
                    }
                }
                _ => {}
            }

            offset += 5 + record_body_len;
        }

        // Put remaining unparsed bytes back, zeroize consumed portion
        if let Some(conn) = self.connections.get_mut(key) {
            let leftover = buffer[offset..].to_vec();
            if from_client {
                conn.from_client_buf = leftover;
            } else {
                conn.from_server_buf = leftover;
            }
        }
        // Zeroize the taken buffer — it may contain TLS record data
        let mut buffer = buffer;
        buffer.zeroize();
    }

    /// M8: Accumulate handshake record data and dispatch complete messages.
    /// Handles handshake messages that span multiple TLS records by buffering
    /// until the full message (per the 3-byte length field) is available.
    fn accumulate_handshake(
        &mut self,
        key: &StreamKey,
        data: &[u8],
        from_client: bool,
        src_ip: IpAddr,
        src_port: u16,
    ) {
        // Append data to the direction's handshake buffer, then extract all
        // complete messages (a single TLS record can contain multiple handshake
        // messages). We extract one message per iteration while holding the
        // borrow, release it to call process_handshake, then re-acquire.
        // Check overflow before taking mutable borrow for extend.
        let overflow = match self.connections.get(key) {
            Some(conn) => {
                let buf_len = if from_client {
                    conn.handshake_buf_client.len()
                } else {
                    conn.handshake_buf_server.len()
                };
                buf_len + data.len() > MAX_HANDSHAKE_BUF
            }
            None => return,
        };
        if overflow {
            self.connections.remove(key);
            return;
        }
        {
            let conn = match self.connections.get_mut(key) {
                Some(c) => c,
                None => return,
            };
            if from_client {
                conn.handshake_buf_client.extend_from_slice(data);
            } else {
                conn.handshake_buf_server.extend_from_slice(data);
            }
        }

        loop {
            let complete_msg = {
                let conn = match self.connections.get_mut(key) {
                    Some(c) => c,
                    None => return,
                };
                let buf = if from_client {
                    &mut conn.handshake_buf_client
                } else {
                    &mut conn.handshake_buf_server
                };

                // Need at least 4 bytes for a handshake header: type(1) + length(3)
                if buf.len() < 4 {
                    break;
                }

                let msg_len =
                    ((buf[1] as usize) << 16) | ((buf[2] as usize) << 8) | (buf[3] as usize);
                let total_len = 4 + msg_len;

                if buf.len() < total_len {
                    break; // Incomplete — wait for more records
                }

                let msg = buf[..total_len].to_vec();
                buf.drain(..total_len);
                msg
            };

            self.process_handshake(key, &complete_msg, src_ip, src_port);
            // Zeroize the extracted handshake message — it may contain key material
            let mut complete_msg = complete_msg;
            complete_msg.zeroize();
        }
    }

    fn process_handshake(&mut self, key: &StreamKey, data: &[u8], src_ip: IpAddr, src_port: u16) {
        let current_version = self.connections.get(key).and_then(|c| c.version);
        let result = match handshake::parse_handshake(data, src_ip, src_port, current_version) {
            Some(r) => r,
            None => return,
        };

        // Issue #9: Use get_mut instead of entry().or_insert_with() to avoid
        // recreating a connection that was removed (e.g., due to buffer overflow).
        let conn = match self.connections.get_mut(key) {
            Some(c) => c,
            None => return,
        };

        if let Some(cr) = result.client_random {
            conn.client_random = Some(cr);
        }
        if let Some(addr) = result.client_addr {
            conn.client_addr = Some(addr);
        }
        if let Some(sr) = result.server_random {
            conn.server_random = Some(sr);
        }
        if let Some(cs) = result.cipher_suite {
            conn.cipher_suite = Some(cs);
        }
        if let Some(v) = result.version {
            conn.version = Some(v);
        }

        if result.should_derive {
            self.try_derive_keys(key);
        }
    }

    fn try_derive_keys(&mut self, key: &StreamKey) {
        // Extract all needed values from the immutable borrow, then release it
        let (client_random, cipher, version) = {
            let conn = match self.connections.get(key) {
                Some(c) => c,
                None => return,
            };
            if conn.client_keys.is_some() {
                return;
            }
            let cr = match conn.client_random {
                Some(cr) => cr,
                None => return,
            };
            let cs = match conn.cipher_suite {
                Some(c) => c,
                None => return,
            };
            // L23: Require explicit version instead of defaulting to TLS 1.2
            let v = match conn.version {
                Some(v) => v,
                None => return,
            };
            (cr, cs, v)
        };

        let (aead_algo, hash_algo, key_len, iv_len, hmac_algo) =
            match handshake::cipher_suite_params(cipher) {
                Some(p) => p,
                None => return,
            };

        // Store iv_len on the connection for use during decryption
        if let Some(conn) = self.connections.get_mut(key) {
            conn.iv_len = iv_len;
        }

        if version == TlsVersion::Tls13 {
            self.derive_tls13_keys(key, &client_random, hash_algo, aead_algo);
        } else {
            self.derive_tls12_keys(key, &client_random, key_len, iv_len, aead_algo, hmac_algo);
        }
    }

    fn derive_tls13_keys(
        &mut self,
        key: &StreamKey,
        client_random: &[u8; 32],
        hash_algo: hkdf::Algorithm,
        aead_algo: &'static aead::Algorithm,
    ) {
        let mut secrets = match self.keylog.tls13_secrets.get(client_random) {
            Some(s) => s.clone(),
            None => return,
        };

        let conn = match self.connections.get_mut(key) {
            Some(c) => c,
            None => {
                secrets.zeroize();
                return;
            }
        };

        // Derive application traffic keys
        if let Some(ref client_secret) = secrets.client_traffic_secret_0
            && let Ok(keys) = decrypt::derive_tls13_keys(client_secret, hash_algo, aead_algo)
        {
            conn.client_keys = Some(keys);
        }
        if let Some(ref server_secret) = secrets.server_traffic_secret_0
            && let Ok(keys) = decrypt::derive_tls13_keys(server_secret, hash_algo, aead_algo)
        {
            conn.server_keys = Some(keys);
        }

        // Derive handshake traffic keys (for encrypted handshake messages)
        if let Some(ref client_hs_secret) = secrets.client_handshake_traffic_secret
            && let Ok(keys) = decrypt::derive_tls13_keys(client_hs_secret, hash_algo, aead_algo)
        {
            conn.client_hs_keys = Some(keys);
        }
        if let Some(ref server_hs_secret) = secrets.server_handshake_traffic_secret
            && let Ok(keys) = decrypt::derive_tls13_keys(server_hs_secret, hash_algo, aead_algo)
        {
            conn.server_hs_keys = Some(keys);
        }
        secrets.zeroize();
    }

    fn derive_tls12_keys(
        &mut self,
        key: &StreamKey,
        client_random: &[u8; 32],
        key_len: usize,
        iv_len: usize,
        aead_algo: &'static aead::Algorithm,
        hmac_algo: ring::hmac::Algorithm,
    ) {
        let mut master_secret = match self.keylog.master_secrets.get(client_random) {
            Some(ms) => ms.clone(),
            None => return,
        };

        let conn = match self.connections.get_mut(key) {
            Some(c) => c,
            None => {
                master_secret.zeroize();
                return;
            }
        };

        let server_random = match conn.server_random {
            Some(sr) => sr,
            None => {
                master_secret.zeroize();
                return;
            }
        };

        if let Ok((client_keys, server_keys)) = decrypt::derive_tls12_keys(
            &master_secret,
            client_random,
            &server_random,
            key_len,
            iv_len,
            aead_algo,
            hmac_algo,
        ) {
            conn.client_keys = Some(client_keys);
            conn.server_keys = Some(server_keys);
        }
        master_secret.zeroize();
    }

    /// Attempt to decrypt a single TLS record.
    ///
    /// M4: If a record is entirely skipped (e.g., buffer truncation in
    /// `drain_buffer` or an unrecognized record type), the per-direction
    /// sequence number won't be incremented, causing all subsequent
    /// decryption attempts for that direction to fail (wrong nonce).
    /// This is a known limitation — accurate record-level parsing is
    /// required for TLS decryption to work.
    fn decrypt_record(
        &mut self,
        key: &StreamKey,
        record: &TlsRawRecord,
        src_ip: IpAddr,
        src_port: u16,
    ) -> Option<Vec<u8>> {
        let conn = self.connections.get_mut(key)?;
        let is_from_client = conn
            .client_addr
            .map(|(ip, port)| ip == src_ip && port == src_port)
            .unwrap_or(false);

        // L23: Require explicit version
        let version = conn.version?;

        if version == TlsVersion::Tls13 {
            self.decrypt_tls13_record(key, record, is_from_client)
        } else {
            self.decrypt_tls12_record_wrapper(key, record, is_from_client)
        }
    }

    /// Try to decrypt a TLS 1.3 record.
    ///
    /// M10: Uses per-direction phase flags to avoid fragile dual-try logic.
    /// Before handshake is complete: try handshake keys, fall back to application keys.
    /// After handshake is complete: only try application keys (no fallback).
    /// This prevents sequence counter desync from incorrect key phase selection.
    fn decrypt_tls13_record(
        &mut self,
        key: &StreamKey,
        record: &TlsRawRecord,
        is_from_client: bool,
    ) -> Option<Vec<u8>> {
        let record_len = record.hdr.len;

        // L5: Build AAD on the stack to avoid per-record heap allocation.
        let version_bytes = u16::from(record.hdr.version).to_be_bytes();
        let len_bytes = record_len.to_be_bytes();
        let aad: [u8; 5] = [
            record.hdr.record_type.0,
            version_bytes[0],
            version_bytes[1],
            len_bytes[0],
            len_bytes[1],
        ];

        let conn = self.connections.get_mut(key)?;

        let hs_complete = if is_from_client {
            conn.client_hs_complete
        } else {
            conn.server_hs_complete
        };

        // Phase 1: Try handshake keys (only if handshake not yet complete for this direction)
        if !hs_complete {
            let hs_keys = if is_from_client {
                conn.client_hs_keys.as_mut()
            } else {
                conn.server_hs_keys.as_mut()
            };
            if let Some(keys) = hs_keys {
                let mut ct = record.data.to_vec();
                let decrypt_result = keys.decrypt_record(&mut ct, &aad);
                ct.zeroize(); // Zeroize in-place decrypted plaintext
                if let Ok(plaintext) = decrypt_result
                    && let Some((data, content_type)) = Self::strip_tls13_content_type(plaintext)
                {
                    if content_type == 0x17 {
                        return Some(data);
                    }
                    // Detect Finished (handshake type 20) — mark handshake complete.
                    // After Finished, this direction switches to application keys,
                    // preventing sequence counter desync from the dual-try fallback.
                    if content_type == 0x16 && data.first() == Some(&20) {
                        if is_from_client {
                            conn.client_hs_complete = true;
                            conn.client_hs_keys = None;
                        } else {
                            conn.server_hs_complete = true;
                            conn.server_hs_keys = None;
                        }
                    }
                    return None;
                }
            }
        }

        // Phase 2: Try application keys
        let app_keys = if is_from_client {
            conn.client_keys.as_mut()
        } else {
            conn.server_keys.as_mut()
        };
        if let Some(keys) = app_keys {
            let mut ct = record.data.to_vec();
            let decrypt_result = keys.decrypt_record(&mut ct, &aad);
            ct.zeroize(); // Zeroize in-place decrypted plaintext
            if let Ok(plaintext) = decrypt_result
                && let Some((data, content_type)) = Self::strip_tls13_content_type(plaintext)
            {
                // Mark handshake as complete for this direction on any
                // successful app-key decryption (not just 0x17). This
                // prevents sequence counter desync from the dual-try fallback.
                if !hs_complete {
                    if is_from_client {
                        conn.client_hs_complete = true;
                        conn.client_hs_keys = None;
                    } else {
                        conn.server_hs_complete = true;
                        conn.server_hs_keys = None;
                    }
                }
                if content_type == 0x17 {
                    return Some(data);
                }
                // M7: Detect KeyUpdate (handshake type 24) — discard keys
                if content_type == 0x16 && data.first() == Some(&24) {
                    eprintln!(
                        "Warning: TLS 1.3 KeyUpdate detected; discarding keys for this direction"
                    );
                    if is_from_client {
                        conn.client_keys = None;
                    } else {
                        conn.server_keys = None;
                    }
                }
                return None;
            }
        }

        None
    }

    /// Strip TLS 1.3 inner content type and trailing zeros from decrypted record.
    /// Returns (plaintext, inner_content_type). Only application data (0x17) should
    /// be added to the decrypted output buffer.
    fn strip_tls13_content_type(mut plaintext: Vec<u8>) -> Option<(Vec<u8>, u8)> {
        while plaintext.last() == Some(&0) {
            plaintext.pop();
        }
        let content_type = plaintext.pop()?;
        Some((plaintext, content_type))
    }

    fn decrypt_tls12_record_wrapper(
        &mut self,
        key: &StreamKey,
        record: &TlsRawRecord,
        is_from_client: bool,
    ) -> Option<Vec<u8>> {
        let conn = self.connections.get_mut(key)?;
        let iv_len = conn.iv_len;
        let keys = if is_from_client {
            conn.client_keys.as_mut()?
        } else {
            conn.server_keys.as_mut()?
        };

        let mut ciphertext = record.data.to_vec();

        match iv_len {
            4 => {
                // AES-GCM: first 8 bytes are explicit nonce, then ciphertext + 16-byte tag
                // Need at least 8 (nonce) + 16 (tag) = 24 bytes minimum
                if ciphertext.len() < 24 {
                    return None;
                }
                let explicit_nonce: Vec<u8> = ciphertext.drain(..8).collect();

                // L5: AAD on the stack: seq_num(8) + type(1) + version(2) + plaintext_length(2)
                let plaintext_len = ciphertext.len() - 16; // minus tag (safe: checked >= 24 above)
                let pt_len_bytes = u16::try_from(plaintext_len).ok()?.to_be_bytes();
                let seq_bytes = keys.seq_num().to_be_bytes();
                let ver_bytes = u16::from(record.hdr.version).to_be_bytes();
                let aad: [u8; 13] = [
                    seq_bytes[0],
                    seq_bytes[1],
                    seq_bytes[2],
                    seq_bytes[3],
                    seq_bytes[4],
                    seq_bytes[5],
                    seq_bytes[6],
                    seq_bytes[7],
                    record.hdr.record_type.0,
                    ver_bytes[0],
                    ver_bytes[1],
                    pt_len_bytes[0],
                    pt_len_bytes[1],
                ];

                let result = keys.decrypt_tls12_record(&mut ciphertext, &aad, &explicit_nonce);
                ciphertext.zeroize(); // Zeroize in-place decrypted plaintext
                result.ok()
            }
            12 => {
                // ChaCha20-Poly1305: no explicit nonce, 16-byte tag appended
                // Need at least 16 (tag) bytes
                if ciphertext.len() < 16 {
                    return None;
                }

                // L5: AAD on the stack: seq_num(8) + type(1) + version(2) + plaintext_length(2)
                let plaintext_len = ciphertext.len() - 16;
                let pt_len_bytes = u16::try_from(plaintext_len).ok()?.to_be_bytes();
                let seq_bytes = keys.seq_num().to_be_bytes();
                let ver_bytes = u16::from(record.hdr.version).to_be_bytes();
                let aad: [u8; 13] = [
                    seq_bytes[0],
                    seq_bytes[1],
                    seq_bytes[2],
                    seq_bytes[3],
                    seq_bytes[4],
                    seq_bytes[5],
                    seq_bytes[6],
                    seq_bytes[7],
                    record.hdr.record_type.0,
                    ver_bytes[0],
                    ver_bytes[1],
                    pt_len_bytes[0],
                    pt_len_bytes[1],
                ];

                // Use build_nonce (XOR seq with full 12-byte IV) via decrypt_record
                let result = keys.decrypt_record(&mut ciphertext, &aad);
                ciphertext.zeroize(); // Zeroize in-place decrypted plaintext
                result.ok()
            }
            _ => None, // Unsupported iv_len
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn max_connections_evicts_oldest() {
        let keylog = KeyLog::default();
        let mut decryptor = TlsDecryptor::new(keylog);
        let src_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let dst_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

        // Fill to MAX_CONNECTIONS with unique stream keys (varying port)
        for i in 0..MAX_CONNECTIONS {
            let key = StreamKey::new(src_ip, i as u16 + 1, dst_ip, 443);
            // Any non-empty payload triggers entry creation
            decryptor.process_packet(&key, &[0xFF], src_ip, i as u16 + 1);
        }
        assert_eq!(decryptor.connections.len(), MAX_CONNECTIONS);

        // One more should evict the oldest (port 1) and admit the new one
        let first_key = StreamKey::new(src_ip, 1, dst_ip, 443);
        let extra_key = StreamKey::new(src_ip, 60000, dst_ip, 443);
        decryptor.process_packet(&extra_key, &[0xFF], src_ip, 60000);
        assert_eq!(decryptor.connections.len(), MAX_CONNECTIONS);
        assert!(decryptor.connections.contains_key(&extra_key));
        assert!(!decryptor.connections.contains_key(&first_key));
    }

    #[test]
    fn max_connections_allows_existing_connection() {
        let keylog = KeyLog::default();
        let mut decryptor = TlsDecryptor::new(keylog);
        let src_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let dst_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

        // Fill to MAX_CONNECTIONS
        for i in 0..MAX_CONNECTIONS {
            let key = StreamKey::new(src_ip, i as u16 + 1, dst_ip, 443);
            decryptor.process_packet(&key, &[0xFF], src_ip, i as u16 + 1);
        }

        // Sending more data to an existing connection should still work
        let existing_key = StreamKey::new(src_ip, 1, dst_ip, 443);
        decryptor.process_packet(&existing_key, &[0xAA], src_ip, 1);
        assert_eq!(decryptor.connections.len(), MAX_CONNECTIONS);
        // Connection still exists (wasn't rejected)
        assert!(decryptor.connections.contains_key(&existing_key));
    }

    // T3: Rewritten — actually tests that get_decrypted stops returning data
    // when decrypted buffer is at the cap, proving the constant is meaningful.
    #[test]
    fn max_decrypted_bytes_caps_buffer() {
        let keylog = KeyLog::default();
        let mut decryptor = TlsDecryptor::new(keylog);
        let src_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let dst_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        let key = StreamKey::new(src_ip, 12345, dst_ip, 443);

        // Manually insert a connection and fill its decrypted buffer
        decryptor.process_packet(&key, &[0xFF], src_ip, 12345);
        let conn = decryptor.connections.get_mut(&key).unwrap();
        conn.decrypted = vec![0xAA; MAX_DECRYPTED_BYTES];

        // get_decrypted should return the full buffer
        let data = decryptor.get_decrypted(&key).unwrap();
        assert_eq!(data.len(), MAX_DECRYPTED_BYTES);

        // After draining, no more data available
        assert!(decryptor.get_decrypted(&key).is_none());
    }

    #[test]
    fn strip_tls13_content_type_application_data() {
        let plaintext = vec![b'h', b'e', b'l', b'l', b'o', 0x17]; // 0x17 = application data
        let (data, ct) = TlsDecryptor::strip_tls13_content_type(plaintext).unwrap();
        assert_eq!(data, b"hello");
        assert_eq!(ct, 0x17);
    }

    #[test]
    fn strip_tls13_content_type_strips_trailing_zeros() {
        let plaintext = vec![b'h', b'i', 0x17, 0x00, 0x00]; // trailing padding zeros
        // Zeros are stripped first, then content type byte
        // After stripping zeros: [b'h', b'i', 0x17]
        // Pop content type: 0x17, data = [b'h', b'i']
        let (data, ct) = TlsDecryptor::strip_tls13_content_type(plaintext).unwrap();
        assert_eq!(data, b"hi");
        assert_eq!(ct, 0x17);
    }

    #[test]
    fn strip_tls13_content_type_empty_returns_none() {
        let plaintext = vec![];
        assert!(TlsDecryptor::strip_tls13_content_type(plaintext).is_none());
    }

    #[test]
    fn strip_tls13_content_type_all_zeros_returns_none() {
        let plaintext = vec![0x00, 0x00, 0x00];
        assert!(TlsDecryptor::strip_tls13_content_type(plaintext).is_none());
    }

    #[test]
    fn tls_connection_is_from_client() {
        let mut conn = TlsConnection::new();
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        conn.client_addr = Some((ip, 5000));

        assert!(conn.is_from_client(ip, 5000));
        assert!(!conn.is_from_client(ip, 5001));
        assert!(!conn.is_from_client(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2)), 5000));
    }

    #[test]
    fn tls_connection_default_client_detection() {
        let conn = TlsConnection::new();
        // Before ClientHello, any sender is treated as client
        let any_ip = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
        assert!(conn.is_from_client(any_ip, 12345));
    }

    #[test]
    fn tls12_chacha20_decrypt_roundtrip() {
        // Generate a ChaCha20-Poly1305 key and IV, encrypt a record, then verify
        // the TLS 1.2 ChaCha20 path can decrypt it.
        use ring::aead::{self, Aad, LessSafeKey, Nonce, UnboundKey};

        let key_bytes = [0x42u8; 32];
        let iv = [0x01u8; 12];

        // Build the nonce: IV XOR seq_num (seq=0, so nonce == IV)
        let nonce_bytes = iv; // seq 0 XOR iv = iv

        // Encrypt a test payload
        let plaintext = b"hello chacha20";
        let mut in_out = plaintext.to_vec();

        // Build AAD for TLS 1.2: seq(8) + type(1) + version(2) + plaintext_len(2)
        let mut aad_bytes = Vec::with_capacity(13);
        aad_bytes.extend_from_slice(&0u64.to_be_bytes()); // seq = 0
        aad_bytes.push(0x17); // application data
        aad_bytes.extend_from_slice(&[0x03, 0x03]); // TLS 1.2
        aad_bytes.extend_from_slice(&(plaintext.len() as u16).to_be_bytes());

        let unbound = UnboundKey::new(&aead::CHACHA20_POLY1305, &key_bytes).unwrap();
        let sealing_key = LessSafeKey::new(unbound);
        let nonce = Nonce::try_assume_unique_for_key(&nonce_bytes).unwrap();
        sealing_key
            .seal_in_place_append_tag(nonce, Aad::from(&aad_bytes), &mut in_out)
            .unwrap();

        // Now decrypt using DirectionKeys (ChaCha20 path: decrypt_record with XOR nonce)
        let mut keys =
            decrypt::DirectionKeys::new(&key_bytes, &iv, &aead::CHACHA20_POLY1305).unwrap();
        let result = keys.decrypt_record(&mut in_out, &aad_bytes).unwrap();
        assert_eq!(result, plaintext);
    }

    #[test]
    fn tls_connection_default_iv_len() {
        let conn = TlsConnection::new();
        assert_eq!(conn.iv_len, 4);
    }

    // T12: Test MAX_BUFFER_BYTES enforcement — connection removed on overflow
    #[test]
    fn max_buffer_bytes_removes_on_overflow() {
        let keylog = KeyLog::default();
        let mut decryptor = TlsDecryptor::new(keylog);
        let src_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let dst_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        let key = StreamKey::new(src_ip, 12345, dst_ip, 443);

        // First packet creates the connection
        decryptor.process_packet(&key, &[0x16, 0x03, 0x01], src_ip, 12345);
        assert!(decryptor.connections.contains_key(&key));

        // Fill the buffer close to MAX_BUFFER_BYTES
        let conn = decryptor.connections.get_mut(&key).unwrap();
        conn.from_client_buf = vec![0xFF; MAX_BUFFER_BYTES - 10];

        // Next packet should overflow and remove the connection entirely
        let big_payload = vec![0xAA; 100];
        decryptor.process_packet(&key, &big_payload, src_ip, 12345);
        assert!(!decryptor.connections.contains_key(&key));
    }

    // T12b: Server direction buffer also enforced
    #[test]
    fn max_buffer_bytes_server_direction() {
        let keylog = KeyLog::default();
        let mut decryptor = TlsDecryptor::new(keylog);
        let client_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let server_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        let key = StreamKey::new(client_ip, 12345, server_ip, 443);

        // Create connection and set client addr
        decryptor.process_packet(&key, &[0x16], client_ip, 12345);
        let conn = decryptor.connections.get_mut(&key).unwrap();
        conn.client_addr = Some((client_ip, 12345));
        conn.from_server_buf = vec![0xFF; MAX_BUFFER_BYTES - 5];

        // Server packet should overflow and remove the connection
        let big_payload = vec![0xBB; 50];
        decryptor.process_packet(&key, &big_payload, server_ip, 443);
        assert!(!decryptor.connections.contains_key(&key));
    }
}
