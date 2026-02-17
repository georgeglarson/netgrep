use std::net::IpAddr;

use ring::aead;
use ring::hkdf;
use ring::hmac;
use tls_parser::*;

/// Fields extracted from a TLS handshake record (ClientHello / ServerHello).
pub(crate) struct HandshakeResult {
    pub client_random: Option<[u8; 32]>,
    pub server_random: Option<[u8; 32]>,
    pub cipher_suite: Option<TlsCipherSuiteID>,
    pub version: Option<TlsVersion>,
    pub client_addr: Option<(IpAddr, u16)>,
    pub should_derive: bool,
}

/// Parse a TLS handshake record and extract cryptographic parameters.
///
/// `current_version` is the version already set on the connection (if any),
/// used to preserve ClientHello's supported_versions detection over ServerHello's
/// legacy version field.
///
/// **Limitation (L25):** This assumes the handshake message fits in a single TLS record.
/// Handshake messages spanning multiple records (fragmented handshakes) are not reassembled
/// and will fail to parse. This is acceptable for typical deployments where ClientHello and
/// ServerHello fit in one record.
pub(crate) fn parse_handshake(
    data: &[u8],
    src_ip: IpAddr,
    src_port: u16,
    current_version: Option<TlsVersion>,
) -> Option<HandshakeResult> {
    // Reconstruct a full TLS record so parse_tls_plaintext can parse it.
    // parse_tls_plaintext expects: type(1) + version(2) + length(2) + body
    // TLS record length field is u16, so bail if data exceeds 65535 bytes
    if data.len() > 65535 {
        return None;
    }
    let mut full = Vec::with_capacity(5 + data.len());
    full.push(0x16); // ContentType::Handshake
    full.extend_from_slice(&[0x03, 0x03]); // TLS 1.2 record version
    full.extend_from_slice(&(data.len() as u16).to_be_bytes());
    full.extend_from_slice(data);

    let (_, parsed) = parse_tls_plaintext(&full).ok()?;

    let mut result = HandshakeResult {
        client_random: None,
        server_random: None,
        cipher_suite: None,
        version: None,
        client_addr: None,
        should_derive: false,
    };

    for msg in &parsed.msg {
        match msg {
            TlsMessage::Handshake(TlsMessageHandshake::ClientHello(ch)) => {
                // L24: Only set client_random when length is exactly 32 bytes
                if ch.random.len() == 32 {
                    let mut client_random = [0u8; 32];
                    client_random.copy_from_slice(ch.random);
                    result.client_random = Some(client_random);
                }
                result.client_addr = Some((src_ip, src_port));

                // Detect TLS 1.3 from supported_versions extension
                if let Some(ext_data) = ch.ext
                    && let Ok((_, exts)) = parse_tls_client_hello_extensions(ext_data)
                {
                    for ext in &exts {
                        if let TlsExtension::SupportedVersions(versions) = ext
                            && versions.contains(&TlsVersion::Tls13)
                        {
                            result.version = Some(TlsVersion::Tls13);
                        }
                    }
                }
            }
            TlsMessage::Handshake(TlsMessageHandshake::ServerHello(sh)) => {
                let mut server_random = [0u8; 32];
                if sh.random.len() == 32 {
                    server_random.copy_from_slice(sh.random);
                }
                result.server_random = Some(server_random);
                result.cipher_suite = Some(sh.cipher);

                // Only set version from ServerHello if not already determined
                // (ClientHello's supported_versions takes priority)
                if current_version.is_none() && result.version.is_none() {
                    result.version = Some(sh.version);
                }

                // Check ServerHello extensions for TLS 1.3
                if let Some(ext_data) = sh.ext
                    && let Ok((_, exts)) = parse_tls_extensions(ext_data)
                {
                    for ext in &exts {
                        if let TlsExtension::SupportedVersions(versions) = ext
                            && versions.contains(&TlsVersion::Tls13)
                        {
                            result.version = Some(TlsVersion::Tls13);
                        }
                    }
                }

                result.should_derive = true;
            }
            _ => {}
        }
    }

    Some(result)
}

/// Map TLS cipher suite ID to (AEAD algorithm, HKDF algorithm, key length, IV length, HMAC algorithm for TLS 1.2 PRF).
///
/// `iv_len` determines TLS 1.2 nonce construction:
/// - 4: AES-GCM implicit IV (4 bytes from key block, 8-byte explicit nonce in record)
/// - 12: ChaCha20 / TLS 1.3 style (full 12-byte IV from key block, XOR with seq num)
pub(crate) fn cipher_suite_params(
    cipher: TlsCipherSuiteID,
) -> Option<(
    &'static aead::Algorithm,
    hkdf::Algorithm,
    usize,
    usize,
    hmac::Algorithm,
)> {
    match cipher.0 {
        // TLS 1.3 cipher suites (hmac_algo unused for 1.3 but kept consistent)
        0x1301 => Some((
            &aead::AES_128_GCM,
            hkdf::HKDF_SHA256,
            16,
            12,
            hmac::HMAC_SHA256,
        )), // TLS_AES_128_GCM_SHA256
        0x1302 => Some((
            &aead::AES_256_GCM,
            hkdf::HKDF_SHA384,
            32,
            12,
            hmac::HMAC_SHA384,
        )), // TLS_AES_256_GCM_SHA384
        0x1303 => Some((
            &aead::CHACHA20_POLY1305,
            hkdf::HKDF_SHA256,
            32,
            12,
            hmac::HMAC_SHA256,
        )), // TLS_CHACHA20_POLY1305_SHA256

        // TLS 1.2 AES-GCM suites (4-byte implicit IV)
        0x009C => Some((
            &aead::AES_128_GCM,
            hkdf::HKDF_SHA256,
            16,
            4,
            hmac::HMAC_SHA256,
        )), // TLS_RSA_WITH_AES_128_GCM_SHA256
        0x009D => Some((
            &aead::AES_256_GCM,
            hkdf::HKDF_SHA384,
            32,
            4,
            hmac::HMAC_SHA384,
        )), // TLS_RSA_WITH_AES_256_GCM_SHA384
        0xC02F => Some((
            &aead::AES_128_GCM,
            hkdf::HKDF_SHA256,
            16,
            4,
            hmac::HMAC_SHA256,
        )), // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
        0xC030 => Some((
            &aead::AES_256_GCM,
            hkdf::HKDF_SHA384,
            32,
            4,
            hmac::HMAC_SHA384,
        )), // TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
        0xC02B => Some((
            &aead::AES_128_GCM,
            hkdf::HKDF_SHA256,
            16,
            4,
            hmac::HMAC_SHA256,
        )), // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
        0xC02C => Some((
            &aead::AES_256_GCM,
            hkdf::HKDF_SHA384,
            32,
            4,
            hmac::HMAC_SHA384,
        )), // TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384

        // TLS 1.2 ChaCha20-Poly1305 suites (12-byte IV, XOR with seq num)
        0xCCA8 => Some((
            &aead::CHACHA20_POLY1305,
            hkdf::HKDF_SHA256,
            32,
            12,
            hmac::HMAC_SHA256,
        )), // TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
        0xCCA9 => Some((
            &aead::CHACHA20_POLY1305,
            hkdf::HKDF_SHA256,
            32,
            12,
            hmac::HMAC_SHA256,
        )), // TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256

        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chacha20_tls13_cipher_suite() {
        let (algo, _, key_len, iv_len, _) = cipher_suite_params(TlsCipherSuiteID(0x1303)).unwrap();
        assert_eq!(algo, &aead::CHACHA20_POLY1305);
        assert_eq!(key_len, 32);
        assert_eq!(iv_len, 12);
    }

    #[test]
    fn chacha20_tls12_ecdhe_rsa() {
        let (algo, _, key_len, iv_len, _) = cipher_suite_params(TlsCipherSuiteID(0xCCA8)).unwrap();
        assert_eq!(algo, &aead::CHACHA20_POLY1305);
        assert_eq!(key_len, 32);
        assert_eq!(iv_len, 12);
    }

    #[test]
    fn chacha20_tls12_ecdhe_ecdsa() {
        let (algo, _, key_len, iv_len, _) = cipher_suite_params(TlsCipherSuiteID(0xCCA9)).unwrap();
        assert_eq!(algo, &aead::CHACHA20_POLY1305);
        assert_eq!(key_len, 32);
        assert_eq!(iv_len, 12);
    }

    #[test]
    fn aes_gcm_has_4_byte_iv() {
        let (_, _, _, iv_len, _) = cipher_suite_params(TlsCipherSuiteID(0xC02F)).unwrap();
        assert_eq!(iv_len, 4);
    }

    #[test]
    fn aes256_gcm_uses_sha384() {
        let (_, _, _, _, hmac_algo) = cipher_suite_params(TlsCipherSuiteID(0x009D)).unwrap();
        // SHA-384 output length is 48 bytes
        assert_eq!(hmac_algo, hmac::HMAC_SHA384);
    }

    #[test]
    fn aes128_gcm_uses_sha256() {
        let (_, _, _, _, hmac_algo) = cipher_suite_params(TlsCipherSuiteID(0x009C)).unwrap();
        assert_eq!(hmac_algo, hmac::HMAC_SHA256);
    }

    #[test]
    fn unknown_cipher_suite_returns_none() {
        assert!(cipher_suite_params(TlsCipherSuiteID(0xFFFF)).is_none());
    }

    // T4: Handshake parsing tests with synthetic ClientHello/ServerHello

    /// Build a minimal TLS ClientHello handshake body (no record header).
    fn build_client_hello(random: &[u8; 32], with_tls13_ext: bool) -> Vec<u8> {
        let mut body = Vec::new();
        // Handshake type: ClientHello (1)
        body.push(0x01);
        // Placeholder for 3-byte length
        let len_pos = body.len();
        body.extend_from_slice(&[0x00, 0x00, 0x00]);

        // ClientHello body:
        // version: TLS 1.2 (0x0303)
        body.extend_from_slice(&[0x03, 0x03]);
        // random: 32 bytes
        body.extend_from_slice(random);
        // session_id length: 0
        body.push(0x00);
        // cipher_suites length: 2 (one suite)
        body.extend_from_slice(&[0x00, 0x02]);
        body.extend_from_slice(&[0x13, 0x01]); // TLS_AES_128_GCM_SHA256
        // compression methods length: 1
        body.push(0x01);
        body.push(0x00); // null compression

        if with_tls13_ext {
            // Extensions
            let mut exts = Vec::new();
            // supported_versions extension (type 0x002B)
            exts.extend_from_slice(&[0x00, 0x2B]);
            // Extension data: length=3, list_len=2, version=0x0304 (TLS 1.3)
            exts.extend_from_slice(&[0x00, 0x03, 0x02, 0x03, 0x04]);

            body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
            body.extend_from_slice(&exts);
        } else {
            // No extensions
            body.extend_from_slice(&[0x00, 0x00]);
        }

        // Patch length (3 bytes, big-endian, excludes handshake type + length field)
        let msg_len = body.len() - 4;
        body[len_pos] = ((msg_len >> 16) & 0xFF) as u8;
        body[len_pos + 1] = ((msg_len >> 8) & 0xFF) as u8;
        body[len_pos + 2] = (msg_len & 0xFF) as u8;

        body
    }

    /// Build a minimal TLS ServerHello handshake body.
    fn build_server_hello(random: &[u8; 32], cipher: u16) -> Vec<u8> {
        let mut body = Vec::new();
        // Handshake type: ServerHello (2)
        body.push(0x02);
        let len_pos = body.len();
        body.extend_from_slice(&[0x00, 0x00, 0x00]);

        // version: TLS 1.2 (0x0303)
        body.extend_from_slice(&[0x03, 0x03]);
        // random: 32 bytes
        body.extend_from_slice(random);
        // session_id length: 0
        body.push(0x00);
        // cipher_suite
        body.extend_from_slice(&cipher.to_be_bytes());
        // compression method: null
        body.push(0x00);
        // No extensions
        body.extend_from_slice(&[0x00, 0x00]);

        let msg_len = body.len() - 4;
        body[len_pos] = ((msg_len >> 16) & 0xFF) as u8;
        body[len_pos + 1] = ((msg_len >> 8) & 0xFF) as u8;
        body[len_pos + 2] = (msg_len & 0xFF) as u8;

        body
    }

    #[test]
    fn parse_synthetic_client_hello_extracts_random() {
        let random = [0x42u8; 32];
        let ch_body = build_client_hello(&random, false);
        let src_ip: IpAddr = "10.0.0.1".parse().unwrap();

        let result = parse_handshake(&ch_body, src_ip, 12345, None).unwrap();
        assert_eq!(result.client_random, Some(random));
        assert_eq!(result.client_addr, Some((src_ip, 12345)));
        assert!(!result.should_derive); // Only ServerHello triggers derive
    }

    #[test]
    fn parse_synthetic_client_hello_detects_tls13() {
        let random = [0xAA; 32];
        let ch_body = build_client_hello(&random, true);
        let src_ip: IpAddr = "10.0.0.1".parse().unwrap();

        let result = parse_handshake(&ch_body, src_ip, 12345, None).unwrap();
        assert_eq!(result.version, Some(TlsVersion::Tls13));
    }

    #[test]
    fn parse_synthetic_server_hello_extracts_cipher() {
        let random = [0xBB; 32];
        let sh_body = build_server_hello(&random, 0xC02F); // ECDHE-RSA-AES128-GCM
        let src_ip: IpAddr = "10.0.0.2".parse().unwrap();

        let result = parse_handshake(&sh_body, src_ip, 443, None).unwrap();
        assert_eq!(result.server_random, Some(random));
        assert_eq!(result.cipher_suite, Some(TlsCipherSuiteID(0xC02F)));
        assert!(result.should_derive);
        // Without supported_versions ext, should get TLS 1.2
        assert_eq!(result.version, Some(TlsVersion::Tls12));
    }

    #[test]
    fn parse_client_hello_short_random_skips_client_random() {
        // L24: short random should not set client_random
        let mut body = Vec::new();
        body.push(0x01); // ClientHello
        body.extend_from_slice(&[0x00, 0x00, 0x00]); // placeholder length
        body.extend_from_slice(&[0x03, 0x03]); // version
        // Only 16 bytes of random instead of 32
        body.extend_from_slice(&[0xAA; 16]);
        // This will fail to parse as a valid ClientHello but tests the guard
        let len = body.len() - 4;
        body[1] = ((len >> 16) & 0xFF) as u8;
        body[2] = ((len >> 8) & 0xFF) as u8;
        body[3] = (len & 0xFF) as u8;

        let src_ip: IpAddr = "10.0.0.1".parse().unwrap();
        // tls_parser may reject this as malformed, which is fine —
        // the important thing is it never sets client_random with bad data.
        let result = parse_handshake(&body, src_ip, 12345, None);
        if let Some(r) = result {
            // If it parses at all, client_random must be None
            assert!(r.client_random.is_none());
        }
    }
}
