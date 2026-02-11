pub mod decrypt;
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

/// Manages TLS decryption across all connections.
pub struct TlsDecryptor {
    keylog: KeyLog,
    connections: HashMap<StreamKey, TlsConnection>,
}

impl TlsDecryptor {
    pub fn new(keylog: KeyLog) -> Self {
        TlsDecryptor {
            keylog,
            connections: HashMap::new(),
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

        let conn = self
            .connections
            .entry(key.clone())
            .or_insert_with(TlsConnection::new);
        let from_client = conn.is_from_client(src_ip, src_port);

        if from_client {
            conn.from_client_buf.extend_from_slice(payload);
        } else {
            conn.from_server_buf.extend_from_slice(payload);
        }

        self.drain_buffer(key, from_client, src_ip, src_port);
    }

    /// Get accumulated decrypted plaintext for a connection.
    /// Returns None if no decrypted data is available.
    pub fn get_decrypted(&self, key: &StreamKey) -> Option<Vec<u8>> {
        let conn = self.connections.get(key)?;
        if conn.decrypted.is_empty() {
            None
        } else {
            Some(conn.decrypted.clone())
        }
    }

    /// Parse complete TLS records from one direction's buffer.
    fn drain_buffer(
        &mut self,
        key: &StreamKey,
        from_client: bool,
        src_ip: IpAddr,
        src_port: u16,
    ) {
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
                c.map(|c| if from_client { c.client_cipher_active } else { c.server_cipher_active })
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
                                conn.decrypted.extend_from_slice(&plaintext);
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

    fn process_handshake(
        &mut self,
        key: &StreamKey,
        data: &[u8],
        src_ip: IpAddr,
        src_port: u16,
    ) {
        // Reconstruct a full TLS record so parse_tls_plaintext can parse it.
        // parse_tls_plaintext expects: type(1) + version(2) + length(2) + body
        let mut full = Vec::with_capacity(5 + data.len());
        full.push(0x16); // ContentType::Handshake
        full.extend_from_slice(&[0x03, 0x03]); // TLS 1.2 record version
        full.extend_from_slice(&(data.len() as u16).to_be_bytes());
        full.extend_from_slice(data);

        let parsed = match parse_tls_plaintext(&full) {
            Ok((_, p)) => p,
            Err(_) => return,
        };

        let mut should_derive = false;

        for msg in &parsed.msg {
            match msg {
                TlsMessage::Handshake(TlsMessageHandshake::ClientHello(ch)) => {
                    let mut client_random = [0u8; 32];
                    if ch.random.len() == 32 {
                        client_random.copy_from_slice(ch.random);
                    }

                    let conn = self
                        .connections
                        .entry(key.clone())
                        .or_insert_with(TlsConnection::new);
                    conn.client_random = Some(client_random);
                    conn.client_addr = Some((src_ip, src_port));

                    // Detect TLS 1.3 from supported_versions extension
                    if let Some(ext_data) = ch.ext {
                        if let Ok((_, exts)) = parse_tls_client_hello_extensions(ext_data) {
                            for ext in &exts {
                                if let TlsExtension::SupportedVersions(versions) = ext {
                                    if versions.contains(&TlsVersion::Tls13) {
                                        conn.version = Some(TlsVersion::Tls13);
                                    }
                                }
                            }
                        }
                    }
                }
                TlsMessage::Handshake(TlsMessageHandshake::ServerHello(sh)) => {
                    if let Some(conn) = self.connections.get_mut(key) {
                        let mut server_random = [0u8; 32];
                        if sh.random.len() == 32 {
                            server_random.copy_from_slice(sh.random);
                        }
                        conn.server_random = Some(server_random);
                        conn.cipher_suite = Some(sh.cipher);

                        if conn.version.is_none() {
                            conn.version = Some(sh.version);
                        }
                        if let Some(ext_data) = sh.ext {
                            if let Ok((_, exts)) = parse_tls_extensions(ext_data) {
                                for ext in &exts {
                                    if let TlsExtension::SupportedVersions(versions) = ext {
                                        if versions.contains(&TlsVersion::Tls13) {
                                            conn.version = Some(TlsVersion::Tls13);
                                        }
                                    }
                                }
                            }
                        }
                    }
                    should_derive = true;
                }
                _ => {}
            }
        }

        if should_derive {
            self.try_derive_keys(key);
        }
    }

    fn try_derive_keys(&mut self, key: &StreamKey) {
        let conn = match self.connections.get(key) {
            Some(c) => c,
            None => return,
        };

        if conn.client_keys.is_some() {
            return;
        }

        let client_random = match conn.client_random {
            Some(cr) => cr,
            None => return,
        };

        let cipher = match conn.cipher_suite {
            Some(c) => c,
            None => return,
        };

        let (aead_algo, hash_algo, key_len) = match cipher_suite_params(cipher) {
            Some(p) => p,
            None => return,
        };

        let version = conn.version.unwrap_or(TlsVersion::Tls12);

        if version == TlsVersion::Tls13 {
            self.derive_tls13_keys(key, &client_random, hash_algo, aead_algo);
        } else {
            self.derive_tls12_keys(key, &client_random, key_len, aead_algo);
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
            4, // GCM implicit IV length
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
        // Build AAD (same for all attempts)
        let mut aad = Vec::with_capacity(5);
        aad.push(record.hdr.record_type.0);
        aad.extend_from_slice(&u16::from(record.hdr.version).to_be_bytes());
        aad.extend_from_slice(&(record.hdr.len as u16).to_be_bytes());

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
        let keys = if is_from_client {
            conn.client_keys.as_mut()?
        } else {
            conn.server_keys.as_mut()?
        };

        let mut ciphertext = record.data.to_vec();

        // TLS 1.2 with GCM: first 8 bytes are the explicit nonce
        if ciphertext.len() < 8 {
            return None;
        }
        let explicit_nonce: Vec<u8> = ciphertext.drain(..8).collect();

        // AAD: seq_num(8) + type(1) + version(2) + plaintext_length(2)
        let plaintext_len = ciphertext.len().saturating_sub(16); // minus GCM tag
        let mut aad = Vec::with_capacity(13);
        aad.extend_from_slice(&(keys.seq_num()).to_be_bytes());
        aad.push(record.hdr.record_type.0);
        aad.extend_from_slice(&u16::from(record.hdr.version).to_be_bytes());
        aad.extend_from_slice(&(plaintext_len as u16).to_be_bytes());

        keys.decrypt_tls12_record(&mut ciphertext, &aad, &explicit_nonce)
            .ok()
    }
}

/// Map TLS cipher suite to (AEAD algorithm, HKDF algorithm, key length).
fn cipher_suite_params(
    cipher: TlsCipherSuiteID,
) -> Option<(&'static aead::Algorithm, hkdf::Algorithm, usize)> {
    match cipher.0 {
        // TLS 1.3 cipher suites
        0x1301 => Some((&aead::AES_128_GCM, hkdf::HKDF_SHA256, 16)), // TLS_AES_128_GCM_SHA256
        0x1302 => Some((&aead::AES_256_GCM, hkdf::HKDF_SHA384, 32)), // TLS_AES_256_GCM_SHA384

        // TLS 1.2 common AES-GCM suites
        0x009C => Some((&aead::AES_128_GCM, hkdf::HKDF_SHA256, 16)), // TLS_RSA_WITH_AES_128_GCM_SHA256
        0x009D => Some((&aead::AES_256_GCM, hkdf::HKDF_SHA384, 32)), // TLS_RSA_WITH_AES_256_GCM_SHA384
        0xC02F => Some((&aead::AES_128_GCM, hkdf::HKDF_SHA256, 16)), // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
        0xC030 => Some((&aead::AES_256_GCM, hkdf::HKDF_SHA384, 32)), // TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
        0xC02B => Some((&aead::AES_128_GCM, hkdf::HKDF_SHA256, 16)), // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
        0xC02C => Some((&aead::AES_256_GCM, hkdf::HKDF_SHA384, 32)), // TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384

        _ => None,
    }
}
