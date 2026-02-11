use anyhow::Result;
use ring::aead::{self, LessSafeKey, UnboundKey};
use ring::hkdf;
use ring::hmac;

/// Derived encryption keys for one direction of a TLS connection.
pub struct DirectionKeys {
    key: LessSafeKey,
    iv: [u8; 12],
    seq: u64,
}

impl DirectionKeys {
    pub fn new(key_bytes: &[u8], iv_bytes: &[u8; 12], algo: &'static aead::Algorithm) -> Result<Self> {
        let unbound = UnboundKey::new(algo, key_bytes).map_err(|_| anyhow::anyhow!("Invalid key"))?;
        Ok(DirectionKeys {
            key: LessSafeKey::new(unbound),
            iv: *iv_bytes,
            seq: 0,
        })
    }

    /// Decrypt a TLS record in place. Returns the plaintext slice.
    /// For TLS 1.3, the additional_data is the record header (5 bytes).
    /// For TLS 1.2, the additional_data is: seq(8) + type(1) + version(2) + length(2).
    pub fn decrypt_record(&mut self, ciphertext: &mut Vec<u8>, additional_data: &[u8]) -> Result<Vec<u8>> {
        let nonce = self.build_nonce();

        let nonce = aead::Nonce::try_assume_unique_for_key(&nonce)
            .map_err(|_| anyhow::anyhow!("Invalid nonce"))?;
        let aad = aead::Aad::from(additional_data);

        let plaintext = self
            .key
            .open_in_place(nonce, aad, ciphertext)
            .map_err(|_| anyhow::anyhow!("Decryption failed"))?;

        // Only advance sequence number on successful decryption
        self.seq += 1;

        Ok(plaintext.to_vec())
    }

    /// Get current sequence number (for TLS 1.2 AAD construction).
    pub fn seq_num(&self) -> u64 {
        self.seq
    }

    /// Decrypt a TLS 1.2 GCM record with explicit nonce.
    /// The full nonce is: implicit_iv[0..4] || explicit_nonce[0..8].
    pub fn decrypt_tls12_record(
        &mut self,
        ciphertext: &mut Vec<u8>,
        additional_data: &[u8],
        explicit_nonce: &[u8],
    ) -> Result<Vec<u8>> {
        let mut nonce = [0u8; 12];
        nonce[..4].copy_from_slice(&self.iv[..4]);
        let copy_len = explicit_nonce.len().min(8);
        nonce[4..4 + copy_len].copy_from_slice(&explicit_nonce[..copy_len]);

        let nonce =
            aead::Nonce::try_assume_unique_for_key(&nonce).map_err(|_| anyhow::anyhow!("Invalid nonce"))?;
        let aad = aead::Aad::from(additional_data);

        let plaintext = self
            .key
            .open_in_place(nonce, aad, ciphertext)
            .map_err(|_| anyhow::anyhow!("TLS 1.2 decryption failed"))?;

        self.seq += 1;

        Ok(plaintext.to_vec())
    }

    fn build_nonce(&self) -> [u8; 12] {
        let mut nonce = self.iv;
        let seq_bytes = self.seq.to_be_bytes();
        // XOR the sequence number into the last 8 bytes of the IV
        for i in 0..8 {
            nonce[12 - 8 + i] ^= seq_bytes[i];
        }
        nonce
    }
}

/// Derive TLS 1.3 keys from a traffic secret using HKDF-Expand-Label.
pub fn derive_tls13_keys(
    traffic_secret: &[u8],
    hash_algo: hkdf::Algorithm,
    aead_algo: &'static aead::Algorithm,
) -> Result<DirectionKeys> {
    let prk = hkdf::Prk::new_less_safe(hash_algo, traffic_secret);

    let key_len = aead_algo.key_len();
    let key_bytes = hkdf_expand_label(&prk, b"key", b"", key_len)?;
    let iv_bytes = hkdf_expand_label(&prk, b"iv", b"", 12)?;

    let mut iv = [0u8; 12];
    iv.copy_from_slice(&iv_bytes);

    DirectionKeys::new(&key_bytes, &iv, aead_algo)
}

/// Derive TLS 1.2 keys from master_secret, client_random, server_random.
pub fn derive_tls12_keys(
    master_secret: &[u8],
    client_random: &[u8; 32],
    server_random: &[u8; 32],
    key_len: usize,
    iv_len: usize,
    aead_algo: &'static aead::Algorithm,
) -> Result<(DirectionKeys, DirectionKeys)> {
    let mut seed = Vec::with_capacity(64);
    seed.extend_from_slice(server_random);
    seed.extend_from_slice(client_random);

    // key_block = PRF(master_secret, "key expansion", server_random + client_random)
    // We need: client_write_key(key_len) + server_write_key(key_len) +
    //          client_write_iv(iv_len) + server_write_iv(iv_len)
    let needed = 2 * key_len + 2 * iv_len;
    let key_block = prf_sha256(master_secret, b"key expansion", &seed, needed);

    let mut offset = 0;
    let client_write_key = &key_block[offset..offset + key_len];
    offset += key_len;
    let server_write_key = &key_block[offset..offset + key_len];
    offset += key_len;

    let mut client_iv = [0u8; 12];
    let mut server_iv = [0u8; 12];

    if iv_len == 4 {
        // GCM implicit IV (4 bytes) — explicit nonce is in the record
        client_iv[..4].copy_from_slice(&key_block[offset..offset + 4]);
        offset += 4;
        server_iv[..4].copy_from_slice(&key_block[offset..offset + 4]);
    } else {
        client_iv[..iv_len].copy_from_slice(&key_block[offset..offset + iv_len]);
        offset += iv_len;
        server_iv[..iv_len].copy_from_slice(&key_block[offset..offset + iv_len]);
    }

    Ok((
        DirectionKeys::new(client_write_key, &client_iv, aead_algo)?,
        DirectionKeys::new(server_write_key, &server_iv, aead_algo)?,
    ))
}

/// TLS 1.3 HKDF-Expand-Label (RFC 8446 Section 7.1).
fn hkdf_expand_label(prk: &hkdf::Prk, label: &[u8], context: &[u8], len: usize) -> Result<Vec<u8>> {
    // Build the HkdfLabel structure:
    // uint16 length
    // opaque label<7..255> = "tls13 " + label
    // opaque context<0..255>
    let tls_label_len = 6 + label.len(); // "tls13 " prefix
    let info_len = 2 + 1 + tls_label_len + 1 + context.len();
    let mut info = Vec::with_capacity(info_len);
    info.extend_from_slice(&(len as u16).to_be_bytes());
    info.push(tls_label_len as u8);
    info.extend_from_slice(b"tls13 ");
    info.extend_from_slice(label);
    info.push(context.len() as u8);
    info.extend_from_slice(context);

    let info_slice = [info.as_slice()];
    let okm = prk
        .expand(&info_slice, HkdfLen(len))
        .map_err(|_| anyhow::anyhow!("HKDF expand failed"))?;

    let mut out = vec![0u8; len];
    okm.fill(&mut out)
        .map_err(|_| anyhow::anyhow!("HKDF fill failed"))?;
    Ok(out)
}

/// TLS 1.2 PRF using HMAC-SHA256.
fn prf_sha256(secret: &[u8], label: &[u8], seed: &[u8], out_len: usize) -> Vec<u8> {
    let key = hmac::Key::new(hmac::HMAC_SHA256, secret);
    let mut label_seed = Vec::with_capacity(label.len() + seed.len());
    label_seed.extend_from_slice(label);
    label_seed.extend_from_slice(seed);

    // A(0) = label_seed, A(i) = HMAC(secret, A(i-1))
    let mut a = hmac::sign(&key, &label_seed).as_ref().to_vec();
    let mut result = Vec::with_capacity(out_len);

    while result.len() < out_len {
        let mut input = Vec::with_capacity(a.len() + label_seed.len());
        input.extend_from_slice(&a);
        input.extend_from_slice(&label_seed);
        result.extend_from_slice(hmac::sign(&key, &input).as_ref());
        a = hmac::sign(&key, &a).as_ref().to_vec();
    }

    result.truncate(out_len);
    result
}

/// Helper type for ring's HKDF output length.
struct HkdfLen(usize);

impl hkdf::KeyType for HkdfLen {
    fn len(&self) -> usize {
        self.0
    }
}
