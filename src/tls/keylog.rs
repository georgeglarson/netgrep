use anyhow::{Context, Result};
use std::collections::HashMap;
use std::path::Path;
use zeroize::Zeroize;

/// Secrets extracted from an SSLKEYLOGFILE, keyed by client_random.
#[derive(Default)]
pub struct KeyLog {
    /// TLS 1.2: CLIENT_RANDOM -> master_secret (48 bytes)
    pub master_secrets: HashMap<[u8; 32], Vec<u8>>,
    /// TLS 1.3: CLIENT_RANDOM -> traffic secrets
    pub tls13_secrets: HashMap<[u8; 32], Tls13Secrets>,
}

/// TLS 1.3 per-connection secrets (handshake + application traffic keys).
#[derive(Default, Clone, Zeroize)]
#[zeroize(drop)]
pub struct Tls13Secrets {
    pub client_handshake_traffic_secret: Option<Vec<u8>>,
    pub server_handshake_traffic_secret: Option<Vec<u8>>,
    pub client_traffic_secret_0: Option<Vec<u8>>,
    pub server_traffic_secret_0: Option<Vec<u8>>,
    /// L26: Retained for future 0-RTT (early data) decryption support.
    pub client_early_traffic_secret: Option<Vec<u8>>,
}

impl Drop for KeyLog {
    fn drop(&mut self) {
        for secret in self.master_secrets.values_mut() {
            secret.zeroize();
        }
    }
}

impl KeyLog {
    /// Maximum keylog file size (50 MB) to prevent excessive memory allocation.
    const MAX_KEYLOG_SIZE: u64 = 50 * 1024 * 1024;

    pub fn from_file(path: &Path) -> Result<Self> {
        let meta = std::fs::metadata(path)
            .context(format!("Failed to stat keylog: {}", path.display()))?;
        if meta.len() > Self::MAX_KEYLOG_SIZE {
            anyhow::bail!(
                "Keylog file too large ({} bytes, max {}): {}",
                meta.len(),
                Self::MAX_KEYLOG_SIZE,
                path.display()
            );
        }
        let contents = std::fs::read_to_string(path)
            .context(format!("Failed to read keylog: {}", path.display()))?;
        Self::parse(&contents)
    }

    pub fn parse(contents: &str) -> Result<Self> {
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
                "CLIENT_EARLY_TRAFFIC_SECRET" => {
                    keylog
                        .tls13_secrets
                        .entry(client_random)
                        .or_default()
                        .client_early_traffic_secret = Some(secret);
                }
                _ => {}
            }
        }

        Ok(keylog)
    }
}

fn decode_hex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) || !s.is_ascii() {
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

    // T13: KeyLog edge case tests

    #[test]
    fn parse_empty_keylog() {
        let kl = KeyLog::parse("").unwrap();
        assert!(kl.master_secrets.is_empty());
        assert!(kl.tls13_secrets.is_empty());
    }

    #[test]
    fn parse_comments_and_blank_lines() {
        let content = "# This is a comment\n\n  # Another comment\n  \n";
        let kl = KeyLog::parse(content).unwrap();
        assert!(kl.master_secrets.is_empty());
        assert!(kl.tls13_secrets.is_empty());
    }

    #[test]
    fn parse_malformed_lines_skipped() {
        let cr = "aa".repeat(32);
        let secret = "bb".repeat(48);
        let content = format!(
            "UNKNOWN_LABEL {} {}\nBAD_FORMAT no_second_field\nTOO FEW\nCLIENT_RANDOM {} {}\n",
            cr, secret, cr, secret
        );
        let kl = KeyLog::parse(&content).unwrap();
        // Only the valid CLIENT_RANDOM line should be parsed
        assert_eq!(kl.master_secrets.len(), 1);
    }

    #[test]
    fn parse_invalid_hex_skipped() {
        // Odd-length hex for client_random
        let content = "CLIENT_RANDOM abc 001122334455\n";
        let kl = KeyLog::parse(content).unwrap();
        assert!(kl.master_secrets.is_empty());
    }

    #[test]
    fn parse_wrong_length_client_random_skipped() {
        // Valid hex but not 32 bytes (only 16 bytes = 32 hex chars)
        let cr_short = "aa".repeat(16);
        let secret = "bb".repeat(48);
        let content = format!("CLIENT_RANDOM {} {}\n", cr_short, secret);
        let kl = KeyLog::parse(&content).unwrap();
        assert!(kl.master_secrets.is_empty());
    }

    #[test]
    fn parse_client_early_traffic_secret() {
        let cr = "cc".repeat(32);
        let secret = "dd".repeat(32);
        let content = format!("CLIENT_EARLY_TRAFFIC_SECRET {} {}\n", cr, secret);
        let kl = KeyLog::parse(&content).unwrap();
        assert_eq!(kl.tls13_secrets.len(), 1);
        let secrets = kl.tls13_secrets.values().next().unwrap();
        assert!(secrets.client_early_traffic_secret.is_some());
    }

    #[test]
    fn keylog_from_nonexistent_file_returns_error() {
        let result = KeyLog::from_file(std::path::Path::new("/nonexistent/path/keylog.txt"));
        assert!(result.is_err());
    }
}
