use anyhow::{Context, Result};
use std::collections::HashMap;
use std::path::Path;

/// Secrets extracted from an SSLKEYLOGFILE, keyed by client_random.
#[derive(Default)]
pub struct KeyLog {
    /// TLS 1.2: CLIENT_RANDOM -> master_secret (48 bytes)
    pub master_secrets: HashMap<[u8; 32], Vec<u8>>,
    /// TLS 1.3: CLIENT_RANDOM -> traffic secrets
    pub tls13_secrets: HashMap<[u8; 32], Tls13Secrets>,
}

#[derive(Default, Clone)]
pub struct Tls13Secrets {
    pub client_handshake_traffic_secret: Option<Vec<u8>>,
    pub server_handshake_traffic_secret: Option<Vec<u8>>,
    pub client_traffic_secret_0: Option<Vec<u8>>,
    pub server_traffic_secret_0: Option<Vec<u8>>,
}

impl KeyLog {
    pub fn from_file(path: &Path) -> Result<Self> {
        let contents = std::fs::read_to_string(path)
            .context(format!("Failed to read keylog: {}", path.display()))?;
        Self::parse(&contents)
    }

    fn parse(contents: &str) -> Result<Self> {
        let mut keylog = KeyLog::default();

        for line in contents.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            let parts: Vec<&str> = line.splitn(3, ' ').collect();
            if parts.len() != 3 {
                continue;
            }

            let label = parts[0];
            let client_random = match decode_hex_32(parts[1]) {
                Some(cr) => cr,
                None => continue,
            };
            let secret = match decode_hex(parts[2]) {
                Some(s) => s,
                None => continue,
            };

            match label {
                "CLIENT_RANDOM" => {
                    keylog.master_secrets.insert(client_random, secret);
                }
                "CLIENT_HANDSHAKE_TRAFFIC_SECRET" => {
                    keylog
                        .tls13_secrets
                        .entry(client_random)
                        .or_default()
                        .client_handshake_traffic_secret = Some(secret);
                }
                "SERVER_HANDSHAKE_TRAFFIC_SECRET" => {
                    keylog
                        .tls13_secrets
                        .entry(client_random)
                        .or_default()
                        .server_handshake_traffic_secret = Some(secret);
                }
                "CLIENT_TRAFFIC_SECRET_0" => {
                    keylog
                        .tls13_secrets
                        .entry(client_random)
                        .or_default()
                        .client_traffic_secret_0 = Some(secret);
                }
                "SERVER_TRAFFIC_SECRET_0" => {
                    keylog
                        .tls13_secrets
                        .entry(client_random)
                        .or_default()
                        .server_traffic_secret_0 = Some(secret);
                }
                _ => {}
            }
        }

        Ok(keylog)
    }
}

fn decode_hex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 || !s.is_ascii() {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

fn decode_hex_32(s: &str) -> Option<[u8; 32]> {
    let bytes = decode_hex(s)?;
    if bytes.len() != 32 {
        return None;
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Some(arr)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_tls12_keylog() {
        let content = "CLIENT_RANDOM aabbccdd00000000000000000000000000000000000000000000000000000000 \
                        0011223344556677889900112233445566778899001122334455667788990011223344556677889900112233445566\n";
        let kl = KeyLog::parse(content).unwrap();
        assert_eq!(kl.master_secrets.len(), 1);
    }

    #[test]
    fn parse_tls13_keylog() {
        let cr = "aa".repeat(32);
        let secret = "bb".repeat(32);
        let content = format!(
            "CLIENT_TRAFFIC_SECRET_0 {} {}\nSERVER_TRAFFIC_SECRET_0 {} {}\n",
            cr, secret, cr, secret
        );
        let kl = KeyLog::parse(&content).unwrap();
        assert_eq!(kl.tls13_secrets.len(), 1);
        let secrets = kl.tls13_secrets.values().next().unwrap();
        assert!(secrets.client_traffic_secret_0.is_some());
        assert!(secrets.server_traffic_secret_0.is_some());
    }
}
