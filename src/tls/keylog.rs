use anyhow::{Context, Result};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use zeroize::Zeroize;

/// Secrets extracted from an SSLKEYLOGFILE, keyed by client_random.
#[derive(Default)]
pub struct KeyLog {
    /// TLS 1.2: CLIENT_RANDOM -> master_secret (48 bytes)
    pub master_secrets: HashMap<[u8; 32], Vec<u8>>,
    /// TLS 1.3: CLIENT_RANDOM -> traffic secrets
    pub tls13_secrets: HashMap<[u8; 32], Tls13Secrets>,
    /// Source file, retained so `refresh()` can re-read secrets appended after
    /// the initial load — SSLKEYLOGFILE is written *during* the sessions we
    /// capture, so a live session's secrets arrive after we first read it.
    source: Option<PathBuf>,
    /// Size of the source at last read, to skip re-parsing an unchanged file.
    last_size: u64,
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
        // L14: Drain both maps so keys (client_random) are also zeroized.
        // Tls13Secrets has #[zeroize(drop)] so values are handled automatically.
        for (mut key, mut secret) in self.master_secrets.drain() {
            key.zeroize();
            secret.zeroize();
        }
        for (mut key, _secrets) in self.tls13_secrets.drain() {
            key.zeroize();
        }
    }
}

impl KeyLog {
    /// Maximum keylog file size (50 MB) to prevent excessive memory allocation.
    const MAX_KEYLOG_SIZE: u64 = 50 * 1024 * 1024;

    pub fn from_file(path: &Path) -> Result<Self> {
        // Read first, then check size to avoid TOCTOU race between metadata() and read().
        let mut raw = match std::fs::read(path) {
            Ok(r) => r,
            // A live capture can start before the client has created the
            // keylog. Tolerate that: start empty, keep the path, and let
            // refresh() pick the secrets up once they appear — rather than
            // aborting the whole capture over a not-yet-written file.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                eprintln!(
                    "Warning: keylog {} not found yet — will read it once it appears",
                    path.display()
                );
                return Ok(KeyLog {
                    master_secrets: HashMap::new(),
                    tls13_secrets: HashMap::new(),
                    source: Some(path.to_path_buf()),
                    last_size: 0,
                });
            }
            Err(e) => {
                return Err(anyhow::Error::new(e))
                    .context(format!("Failed to read keylog: {}", path.display()));
            }
        };
        let read_len = raw.len() as u64;
        if read_len > Self::MAX_KEYLOG_SIZE {
            raw.zeroize();
            anyhow::bail!(
                "Keylog file too large ({} bytes, max {}): {}",
                read_len,
                Self::MAX_KEYLOG_SIZE,
                path.display()
            );
        }
        // Use from_utf8 (not from_utf8_lossy) to avoid creating a separate
        // owned String that would leak secret material without zeroization.
        // Keylog files are ASCII text, so non-UTF-8 content is an error.
        let contents = match std::str::from_utf8(&raw) {
            Ok(s) => s,
            Err(_) => {
                raw.zeroize();
                anyhow::bail!("Keylog file is not valid UTF-8: {}", path.display());
            }
        };
        let mut result = Self::parse(contents);
        raw.zeroize();
        if let Ok(ref mut kl) = result {
            kl.source = Some(path.to_path_buf());
            kl.last_size = read_len;
        }
        result
    }

    /// Re-read the source keylog if it has grown (or was rotated), pulling in
    /// newly-appended secrets. Returns true if the file changed and was
    /// re-parsed. Cheap no-op when there's no source or the size is unchanged.
    ///
    /// This is what makes *live* decryption work: SSLKEYLOGFILE is append-only
    /// and written by the client during the very sessions we're capturing, so
    /// a new session's secrets land after we first read the file. On a decrypt
    /// miss we call this to catch up.
    pub fn refresh(&mut self) -> bool {
        let Some(path) = self.source.clone() else {
            return false;
        };
        let size = match std::fs::metadata(&path) {
            Ok(m) => m.len(),
            // Not there (yet) or unreadable — keep what we have.
            Err(_) => return false,
        };
        // Only act on growth. SSLKEYLOGFILE is append-only, so a larger file is
        // a superset of what we hold and re-parsing is safe. A same-or-smaller
        // size means either nothing new or a rotation/truncation; in the latter
        // case the re-read would be a strict subset, and swapping it in would
        // drop secrets we still hold, so we keep what we have instead.
        if size <= self.last_size {
            return false;
        }
        // The file grew: re-parse the whole thing (bounded by MAX_KEYLOG_SIZE).
        match Self::from_file(&path) {
            // Only accept a re-read at least as large as what we already hold.
            // The file could be unlinked or truncated between the metadata()
            // above and from_file's read (e.g. a log rotator that unlinks-then-
            // recreates rather than atomically renaming); from_file tolerates a
            // vanished file by returning an empty log (last_size 0), and
            // swapping that in would wipe every secret we have. Guard against it.
            Ok(mut fresh) if fresh.last_size >= self.last_size => {
                // Swap the fresh maps in; `fresh` then owns the old maps and
                // its Drop zeroizes them. Keep our own source unchanged.
                std::mem::swap(&mut self.master_secrets, &mut fresh.master_secrets);
                std::mem::swap(&mut self.tls13_secrets, &mut fresh.tls13_secrets);
                self.last_size = fresh.last_size;
                true
            }
            // Re-read came back smaller than we hold (a truncation/unlink race):
            // keep our secrets, and don't advance last_size, so a genuine later
            // growth is still picked up.
            Ok(_) => false,
            // Suppress future full re-reads only for a persistently oversized
            // file — the real per-record I/O risk, and a condition that won't
            // fix itself below this size. A transient read error or a malformed
            // (non-UTF-8) file is left un-cached, so a later good read can still
            // recover rather than being locked out until the file grows.
            Err(_) => {
                if size > Self::MAX_KEYLOG_SIZE {
                    self.last_size = size;
                }
                false
            }
        }
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
            let mut secret = match decode_hex(parts[2]) {
                Some(s) => s,
                None => continue,
            };

            match label {
                "CLIENT_RANDOM" => {
                    // Issue #8: Validate master secret is exactly 48 bytes
                    if secret.len() != 48 {
                        secret.zeroize();
                        continue;
                    }
                    // Zeroize old secret if overwriting
                    if let Some(mut old) = keylog.master_secrets.insert(client_random, secret) {
                        old.zeroize();
                    }
                }
                "CLIENT_HANDSHAKE_TRAFFIC_SECRET" => {
                    let entry = keylog.tls13_secrets.entry(client_random).or_default();
                    if let Some(ref mut old) = entry.client_handshake_traffic_secret {
                        old.zeroize();
                    }
                    entry.client_handshake_traffic_secret = Some(secret);
                }
                "SERVER_HANDSHAKE_TRAFFIC_SECRET" => {
                    let entry = keylog.tls13_secrets.entry(client_random).or_default();
                    if let Some(ref mut old) = entry.server_handshake_traffic_secret {
                        old.zeroize();
                    }
                    entry.server_handshake_traffic_secret = Some(secret);
                }
                "CLIENT_TRAFFIC_SECRET_0" => {
                    let entry = keylog.tls13_secrets.entry(client_random).or_default();
                    if let Some(ref mut old) = entry.client_traffic_secret_0 {
                        old.zeroize();
                    }
                    entry.client_traffic_secret_0 = Some(secret);
                }
                "SERVER_TRAFFIC_SECRET_0" => {
                    let entry = keylog.tls13_secrets.entry(client_random).or_default();
                    if let Some(ref mut old) = entry.server_traffic_secret_0 {
                        old.zeroize();
                    }
                    entry.server_traffic_secret_0 = Some(secret);
                }
                "CLIENT_EARLY_TRAFFIC_SECRET" => {
                    let entry = keylog.tls13_secrets.entry(client_random).or_default();
                    if let Some(ref mut old) = entry.client_early_traffic_secret {
                        old.zeroize();
                    }
                    entry.client_early_traffic_secret = Some(secret);
                }
                _ => {
                    // L3: Zeroize secret for unrecognized labels
                    secret.zeroize();
                }
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
    let mut bytes = decode_hex(s)?;
    if bytes.len() != 32 {
        // L4: Zeroize intermediate hex bytes before returning
        bytes.zeroize();
        return None;
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    bytes.zeroize();
    Some(arr)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_tls12_keylog() {
        let content = "CLIENT_RANDOM aabbccdd00000000000000000000000000000000000000000000000000000000 \
                        001122334455667788990011223344556677889900112233445566778899001122334455667788990011223344556677\n";
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

    // Live-capture support: tolerate a missing keylog at startup, and pick up
    // secrets appended to it after the initial read (the live-monitoring case).

    #[test]
    fn from_file_tolerates_missing_file() {
        // A live capture may start before the client has created the keylog.
        // Missing must be tolerated (empty, source retained for refresh), not
        // a hard error that kills the whole capture.
        let path =
            std::env::temp_dir().join(format!("netgrep_missing_{}.keys", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let kl = KeyLog::from_file(&path).expect("missing keylog should be tolerated");
        assert!(kl.master_secrets.is_empty());
        assert!(kl.tls13_secrets.is_empty());
    }

    #[test]
    fn refresh_picks_up_appended_secrets() {
        use std::io::Write;
        let path =
            std::env::temp_dir().join(format!("netgrep_refresh_{}.keys", std::process::id()));
        let cr1 = "aa".repeat(32);
        let cr2 = "cc".repeat(32);
        let ms = "bb".repeat(48);
        std::fs::write(&path, format!("CLIENT_RANDOM {cr1} {ms}\n")).unwrap();

        let mut kl = KeyLog::from_file(&path).unwrap();
        assert_eq!(kl.master_secrets.len(), 1);

        // A new session's secret is appended after the initial read — exactly
        // what SSLKEYLOGFILE does mid-capture. refresh() must pull it in.
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap();
        writeln!(f, "CLIENT_RANDOM {cr2} {ms}").unwrap();
        drop(f);

        assert!(kl.refresh(), "refresh should report the file grew");
        assert_eq!(
            kl.master_secrets.len(),
            2,
            "appended secret must be picked up"
        );
        assert!(!kl.refresh(), "unchanged file: refresh is a no-op");

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn refresh_completes_a_partial_tls13_entry() {
        // The live-1.3 case that a presence-only refresh gate missed: a client
        // writes its handshake-traffic secrets first (creating a partial entry
        // for the client_random), then its application-traffic secrets once the
        // handshake completes. refresh() must merge the later app secrets into
        // the existing entry, not treat the entry as already complete.
        use std::io::Write;
        let path =
            std::env::temp_dir().join(format!("netgrep_partial13_{}.keys", std::process::id()));
        let cr = "aa".repeat(32);
        let secret = "bb".repeat(32);
        std::fs::write(
            &path,
            format!(
                "CLIENT_HANDSHAKE_TRAFFIC_SECRET {cr} {secret}\n\
                 SERVER_HANDSHAKE_TRAFFIC_SECRET {cr} {secret}\n"
            ),
        )
        .unwrap();

        let mut kl = KeyLog::from_file(&path).unwrap();
        let entry = kl.tls13_secrets.values().next().unwrap();
        assert!(entry.client_handshake_traffic_secret.is_some());
        assert!(
            entry.client_traffic_secret_0.is_none(),
            "app-traffic secret should not be present yet"
        );

        // App-traffic secrets land later, appended for the SAME client_random.
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap();
        writeln!(f, "CLIENT_TRAFFIC_SECRET_0 {cr} {secret}").unwrap();
        writeln!(f, "SERVER_TRAFFIC_SECRET_0 {cr} {secret}").unwrap();
        drop(f);

        assert!(kl.refresh());
        assert_eq!(kl.tls13_secrets.len(), 1, "still one connection");
        let entry = kl.tls13_secrets.values().next().unwrap();
        assert!(
            entry.client_traffic_secret_0.is_some() && entry.server_traffic_secret_0.is_some(),
            "app-traffic secrets appended for the same random must be picked up"
        );

        let _ = std::fs::remove_file(&path);
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
    fn keylog_from_unreadable_path_still_errors() {
        // A *missing* file is now tolerated (see from_file_tolerates_missing_file,
        // for the live-capture case), but a genuine read error must still
        // surface — reading a directory as a keylog is not NotFound.
        let result = KeyLog::from_file(&std::env::temp_dir());
        assert!(
            result.is_err(),
            "reading a directory as a keylog should error"
        );
    }
}
