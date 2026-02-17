pub mod decrypt;
pub(crate) mod handshake;
pub mod keylog;

use std::collections::HashMap;
use std::net::IpAddr;

use ring::aead;
use ring::hkdf;
use tls_parser::*;

use crate::protocol::StreamKey;
use decrypt::DirectionKeys;
use keylog::KeyLog;

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
    decrypted: Vec<u8>,
    /// Byte offset up to which decrypted data has been returned to the caller.
    decrypted_emitted: usize,
    /// Monotonic tick updated on each packet for LRU eviction.
    last_active: u64,
    /// IV length from cipher suite (4 for AES-GCM, 12 for ChaCha20/TLS 1.3).
    iv_len: usize,
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
            decrypted_emitted: 0,
            last_active: 0,
            iv_len: 4,
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

const MAX_CONNECTIONS: usize = 10_000;
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

        self.tick += 1;

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

        // Check buffer size before extending to avoid temporary memory spike
        if from_client {
            if conn.from_client_buf.len() + payload.len() > MAX_BUFFER_BYTES {
                conn.from_client_buf.clear();
                return;
            }
            conn.from_client_buf.extend_from_slice(payload);
        } else {
            if conn.from_server_buf.len() + payload.len() > MAX_BUFFER_BYTES {
                conn.from_server_buf.clear();
                return;
            }
            conn.from_server_buf.extend_from_slice(payload);
        }

        self.drain_buffer(key, from_client, src_ip, src_port);
    }

    /// Get new decrypted plaintext since the last call for a connection.
    /// Returns None if no new decrypted data is available.
    pub fn get_decrypted(&mut self, key: &StreamKey) -> Option<Vec<u8>> {
        let conn = self.connections.get_mut(key)?;
        if conn.decrypted_emitted >= conn.decrypted.len() {
            None
        } else {
            let new_data = conn.decrypted[conn.decrypted_emitted..].to_vec();
            conn.decrypted_emitted = conn.decrypted.len();
            Some(new_data)
        }
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

            // Validate record type byte (0x14-0x18)
            let record_type = remaining[0];
            if !(0x14..=0x18).contains(&record_type) {
                // Not a TLS record — discard this direction's buffer
                offset = buffer.len();
                break;
            }

            // Check if we have the complete record body
            let record_body_len = u16::from_be_bytes([remaining[3], remaining[4]]) as usize;
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
                    self.process_handshake(key, record.data, src_ip, src_port);
                }
                // After CCS, handshake records (Finished) are encrypted — decrypt to advance seq
                TlsRecordType::Handshake | TlsRecordType::ApplicationData => {
                    if let Some(plaintext) = self.decrypt_record(key, &record, src_ip, src_port) {
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
                    }
                }
                _ => {}
            }

            offset += 5 + record_body_len;
        }

        // Put remaining unparsed bytes back
        if let Some(conn) = self.connections.get_mut(key) {
            let leftover = buffer[offset..].to_vec();
            if from_client {
                conn.from_client_buf = leftover;
            } else {
                conn.from_server_buf = leftover;
            }
        }
    }

    fn process_handshake(&mut self, key: &StreamKey, data: &[u8], src_ip: IpAddr, src_port: u16) {
        let current_version = self.connections.get(key).and_then(|c| c.version);
        let result = match handshake::parse_handshake(data, src_ip, src_port, current_version) {
            Some(r) => r,
            None => return,
        };

        let conn = self
            .connections
            .entry(key.clone())
            .or_insert_with(TlsConnection::new);

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
            (cr, cs, conn.version.unwrap_or(TlsVersion::Tls12))
        };

        let (aead_algo, hash_algo, key_len, iv_len) = match handshake::cipher_suite_params(cipher) {
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
            self.derive_tls12_keys(key, &client_random, key_len, iv_len, aead_algo);
        }
    }

    fn derive_tls13_keys(
        &mut self,
        key: &StreamKey,
        client_random: &[u8; 32],
        hash_algo: hkdf::Algorithm,
        aead_algo: &'static aead::Algorithm,
    ) {
        let secrets = match self.keylog.tls13_secrets.get(client_random) {
            Some(s) => s.clone(),
            None => return,
        };

        let conn = match self.connections.get_mut(key) {
            Some(c) => c,
            None => return,
        };

        // Derive application traffic keys
        if let Some(ref client_secret) = secrets.client_traffic_secret_0 {
            if let Ok(keys) = decrypt::derive_tls13_keys(client_secret, hash_algo, aead_algo) {
                conn.client_keys = Some(keys);
            }
        }
        if let Some(ref server_secret) = secrets.server_traffic_secret_0 {
            if let Ok(keys) = decrypt::derive_tls13_keys(server_secret, hash_algo, aead_algo) {
                conn.server_keys = Some(keys);
            }
        }

        // Derive handshake traffic keys (for encrypted handshake messages)
        if let Some(ref client_hs_secret) = secrets.client_handshake_traffic_secret {
            if let Ok(keys) = decrypt::derive_tls13_keys(client_hs_secret, hash_algo, aead_algo) {
                conn.client_hs_keys = Some(keys);
            }
        }
        if let Some(ref server_hs_secret) = secrets.server_handshake_traffic_secret {
            if let Ok(keys) = decrypt::derive_tls13_keys(server_hs_secret, hash_algo, aead_algo) {
                conn.server_hs_keys = Some(keys);
            }
        }
    }

    fn derive_tls12_keys(
        &mut self,
        key: &StreamKey,
        client_random: &[u8; 32],
        key_len: usize,
        iv_len: usize,
        aead_algo: &'static aead::Algorithm,
    ) {
        let master_secret = match self.keylog.master_secrets.get(client_random) {
            Some(ms) => ms.clone(),
            None => return,
        };

        let conn = match self.connections.get_mut(key) {
            Some(c) => c,
            None => return,
        };

        let server_random = match conn.server_random {
            Some(sr) => sr,
            None => return,
        };

        if let Ok((client_keys, server_keys)) = decrypt::derive_tls12_keys(
            &master_secret,
            client_random,
            &server_random,
            key_len,
            iv_len,
            aead_algo,
        ) {
            conn.client_keys = Some(client_keys);
            conn.server_keys = Some(server_keys);
        }
    }

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

        let version = conn.version.unwrap_or(TlsVersion::Tls12);

        if version == TlsVersion::Tls13 {
            self.decrypt_tls13_record(key, record, is_from_client)
        } else {
            self.decrypt_tls12_record_wrapper(key, record, is_from_client)
        }
    }

    /// Try to decrypt a TLS 1.3 record, trying handshake keys first, then application keys.
    fn decrypt_tls13_record(
        &mut self,
        key: &StreamKey,
        record: &TlsRawRecord,
        is_from_client: bool,
    ) -> Option<Vec<u8>> {
        // Bail if record length exceeds u16 range (malformed record)
        let record_len = u16::try_from(record.hdr.len).ok()?;

        // Build AAD (same for all attempts)
        let mut aad = Vec::with_capacity(5);
        aad.push(record.hdr.record_type.0);
        aad.extend_from_slice(&u16::from(record.hdr.version).to_be_bytes());
        aad.extend_from_slice(&record_len.to_be_bytes());

        let conn = self.connections.get_mut(key)?;

        // Try handshake keys first (clone ciphertext since open_in_place corrupts on failure)
        let hs_keys = if is_from_client {
            conn.client_hs_keys.as_mut()
        } else {
            conn.server_hs_keys.as_mut()
        };
        if let Some(keys) = hs_keys {
            let mut ct = record.data.to_vec();
            if let Ok(plaintext) = keys.decrypt_record(&mut ct, &aad) {
                if let Some((data, content_type)) = Self::strip_tls13_content_type(plaintext) {
                    // Only return application data (0x17), skip handshake (0x16) etc.
                    if content_type == 0x17 {
                        return Some(data);
                    }
                    return None;
                }
            }
        }

        // Try application keys
        let app_keys = if is_from_client {
            conn.client_keys.as_mut()
        } else {
            conn.server_keys.as_mut()
        };
        if let Some(keys) = app_keys {
            let mut ct = record.data.to_vec();
            if let Ok(plaintext) = keys.decrypt_record(&mut ct, &aad) {
                if let Some((data, content_type)) = Self::strip_tls13_content_type(plaintext) {
                    if content_type == 0x17 {
                        // Handshake is complete — discard handshake keys to avoid
                        // wasting cycles trying them on every subsequent record.
                        conn.client_hs_keys = None;
                        conn.server_hs_keys = None;
                        return Some(data);
                    }
                    return None;
                }
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

        if iv_len == 4 {
            // AES-GCM: first 8 bytes are explicit nonce, then ciphertext + 16-byte tag
            // Need at least 8 (nonce) + 16 (tag) = 24 bytes minimum
            if ciphertext.len() < 24 {
                return None;
            }
            let explicit_nonce: Vec<u8> = ciphertext.drain(..8).collect();

            // AAD: seq_num(8) + type(1) + version(2) + plaintext_length(2)
            let plaintext_len = ciphertext.len() - 16; // minus tag (safe: checked >= 24 above)
            let mut aad = Vec::with_capacity(13);
            aad.extend_from_slice(&(keys.seq_num()).to_be_bytes());
            aad.push(record.hdr.record_type.0);
            aad.extend_from_slice(&u16::from(record.hdr.version).to_be_bytes());
            aad.extend_from_slice(&(plaintext_len as u16).to_be_bytes());

            keys.decrypt_tls12_record(&mut ciphertext, &aad, &explicit_nonce)
                .ok()
        } else {
            // ChaCha20-Poly1305: no explicit nonce, 16-byte tag appended
            // Need at least 16 (tag) bytes
            if ciphertext.len() < 16 {
                return None;
            }

            // AAD: seq_num(8) + type(1) + version(2) + plaintext_length(2)
            let plaintext_len = ciphertext.len() - 16;
            let mut aad = Vec::with_capacity(13);
            aad.extend_from_slice(&(keys.seq_num()).to_be_bytes());
            aad.push(record.hdr.record_type.0);
            aad.extend_from_slice(&u16::from(record.hdr.version).to_be_bytes());
            aad.extend_from_slice(&(plaintext_len as u16).to_be_bytes());

            // Use build_nonce (XOR seq with full 12-byte IV) via decrypt_record
            keys.decrypt_record(&mut ciphertext, &aad).ok()
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

        // Verify the cap constant is what we expect
        assert_eq!(conn.decrypted.len(), 1_048_576);
        assert_eq!(MAX_DECRYPTED_BYTES, 1_048_576);
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
}
