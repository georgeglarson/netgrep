use std::net::IpAddr;

use ring::aead;
use ring::hkdf;
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
pub(crate) fn parse_handshake(
    data: &[u8],
    src_ip: IpAddr,
    src_port: u16,
    current_version: Option<TlsVersion>,
) -> Option<HandshakeResult> {
    // Reconstruct a full TLS record so parse_tls_plaintext can parse it.
    // parse_tls_plaintext expects: type(1) + version(2) + length(2) + body
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
                let mut client_random = [0u8; 32];
                if ch.random.len() == 32 {
                    client_random.copy_from_slice(ch.random);
                }

                result.client_random = Some(client_random);
                result.client_addr = Some((src_ip, src_port));

                // Detect TLS 1.3 from supported_versions extension
                if let Some(ext_data) = ch.ext {
                    if let Ok((_, exts)) = parse_tls_client_hello_extensions(ext_data) {
                        for ext in &exts {
                            if let TlsExtension::SupportedVersions(versions) = ext {
                                if versions.contains(&TlsVersion::Tls13) {
                                    result.version = Some(TlsVersion::Tls13);
                                }
                            }
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
                if let Some(ext_data) = sh.ext {
                    if let Ok((_, exts)) = parse_tls_extensions(ext_data) {
                        for ext in &exts {
                            if let TlsExtension::SupportedVersions(versions) = ext {
                                if versions.contains(&TlsVersion::Tls13) {
                                    result.version = Some(TlsVersion::Tls13);
                                }
                            }
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

/// Map TLS cipher suite ID to (AEAD algorithm, HKDF algorithm, key length).
pub(crate) fn cipher_suite_params(
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
