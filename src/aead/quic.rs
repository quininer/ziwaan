// Copyright 2018 Brian Smith.
//
// Permission to use, copy, modify, and/or distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
//
// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHORS DISCLAIM ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY
// SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
// OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
// CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

//! QUIC Header Protection.
//!
//! See draft-ietf-quic-tls.

use crate::error;
use core::convert::{TryFrom, TryInto};
use aes::{ cipher, Aes128Enc, Aes256Enc };
use chacha20::ChaChaCore;
use cipher::KeyInit;

/// A key for generating QUIC Header Protection masks.
pub struct HeaderProtectionKey {
    inner: KeyInner,
    algorithm: &'static Algorithm,
}

#[allow(clippy::large_enum_variant, variant_size_differences)]
enum KeyInner {
    Aes128(Aes128Enc),
    Aes256(Aes256Enc),
    ChaCha20(chacha20::Key),
}

/*
impl From<hkdf::Okm<'_, &'static Algorithm>> for HeaderProtectionKey {
    fn from(okm: hkdf::Okm<&'static Algorithm>) -> Self {
        let mut key_bytes = [0; super::MAX_KEY_LEN];
        let algorithm = *okm.len();
        let key_bytes = &mut key_bytes[..algorithm.key_len()];
        okm.fill(key_bytes).unwrap();
        Self::new(algorithm, key_bytes).unwrap()
    }
}
*/

impl HeaderProtectionKey {
    /// Create a new header protection key.
    ///
    /// `key_bytes` must be exactly `algorithm.key_len` bytes long.
    pub fn new(
        algorithm: &'static Algorithm,
        key_bytes: &[u8],
    ) -> Result<Self, error::Unspecified> {
        Ok(Self {
            inner: (algorithm.init)(key_bytes)?,
            algorithm,
        })
    }

    /// Generate a new QUIC Header Protection mask.
    ///
    /// `sample` must be exactly `self.algorithm().sample_len()` bytes long.
    pub fn new_mask(&self, sample: &[u8]) -> Result<[u8; 5], error::Unspecified> {
        let sample = <&[u8; SAMPLE_LEN]>::try_from(sample)?;

        let out = (self.algorithm.new_mask)(&self.inner, *sample);
        Ok(out)
    }

    /// The key's algorithm.
    #[inline(always)]
    pub fn algorithm(&self) -> &'static Algorithm {
        self.algorithm
    }
}

const SAMPLE_LEN: usize = super::TAG_LEN;

/// QUIC sample for new key masks
pub type Sample = [u8; SAMPLE_LEN];

/// A QUIC Header Protection Algorithm.
pub struct Algorithm {
    init: fn(key: &[u8]) -> Result<KeyInner, error::Unspecified>,

    new_mask: fn(key: &KeyInner, sample: Sample) -> [u8; 5],

    key_len: usize,
    id: AlgorithmID,
}

/*
impl hkdf::KeyType for &'static Algorithm {
    #[inline]
    fn len(&self) -> usize {
        self.key_len()
    }
}
*/

impl Algorithm {
    /// The length of the key.
    #[inline(always)]
    pub fn key_len(&self) -> usize {
        self.key_len
    }

    /// The required sample length.
    #[inline(always)]
    pub fn sample_len(&self) -> usize {
        SAMPLE_LEN
    }
}

derive_debug_via_id!(Algorithm);

#[derive(Debug, Eq, PartialEq)]
enum AlgorithmID {
    AES_128,
    AES_256,
    CHACHA20,
}

impl PartialEq for Algorithm {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

impl Eq for Algorithm {}

/// AES-128.
pub static AES_128: Algorithm = Algorithm {
    key_len: AES_128_KEY_LEN,
    init: aes_init_128,
    new_mask: new_mask,
    id: AlgorithmID::AES_128,
};

/// AES-256.
pub static AES_256: Algorithm = Algorithm {
    key_len: AES_256_KEY_LEN,
    init: aes_init_256,
    new_mask: new_mask,
    id: AlgorithmID::AES_256,
};

const AES_128_KEY_LEN: usize = <<Aes128Enc as cipher::KeySizeUser>::KeySize as cipher::Unsigned>::USIZE;
const AES_256_KEY_LEN: usize = <<Aes256Enc as cipher::KeySizeUser>::KeySize as cipher::Unsigned>::USIZE;

fn aes_init_128(key: &[u8]) -> Result<KeyInner, error::Unspecified> {
    let key: [u8; AES_128_KEY_LEN] = key.try_into()?;
    let key: cipher::Key<Aes128Enc> = key.into();
    Ok(KeyInner::Aes128(Aes128Enc::new(&key)))
}

fn aes_init_256(key: &[u8]) -> Result<KeyInner, error::Unspecified> {
    let key: [u8; AES_256_KEY_LEN] = key.try_into()?;
    let key: cipher::Key<Aes256Enc> = key.into();
    Ok(KeyInner::Aes256(Aes256Enc::new(&key)))
}

/// ChaCha20.
pub static CHACHA20: Algorithm = Algorithm {
    key_len: CHACHA20_KEY_LEN,
    init: chacha20_init,
    new_mask: new_mask,
    id: AlgorithmID::CHACHA20,
};

type ChaCha20 = ChaChaCore<cipher::consts::U10>;

const CHACHA20_KEY_LEN: usize = <<ChaCha20 as cipher::KeySizeUser>::KeySize as cipher::Unsigned>::USIZE;

fn chacha20_init(key: &[u8]) -> Result<KeyInner, error::Unspecified> {
    let chacha20_key: [u8; CHACHA20_KEY_LEN] = key.try_into()?;
    Ok(KeyInner::ChaCha20(chacha20::Key::from(chacha20_key)))
}

fn new_mask(key: &KeyInner, sample: Sample) -> [u8; 5] {
    use cipher::{ KeyIvInit, BlockEncrypt, StreamCipherCore, StreamCipherSeekCore };

    match key {
        KeyInner::Aes128(cipher) => {
            let mut block = aes::Block::from(sample);
            cipher.encrypt_block(&mut block);
            let mut out = [0; 5];
            out.copy_from_slice(&block.as_slice()[..5]);
            out
        },
        KeyInner::Aes256(cipher) => {
            let mut block = aes::Block::from(sample);
            cipher.encrypt_block(&mut block);
            let mut out = [0; 5];
            out.copy_from_slice(&block.as_slice()[..5]);
            out
        },
        KeyInner::ChaCha20(key) => {
            let mut nonce = [0; 12];
            nonce.copy_from_slice(&sample[4..]);
            let mut cnt = [0; 4];
            cnt.copy_from_slice(&sample[..4]);
            let cnt = u32::from_le_bytes(cnt);

            let mut cipher = ChaCha20::new(&key, &nonce.into());

            let mut block = Default::default();
            cipher.write_keystream_block(&mut block);
            let mut out = [0; 5];
            out.copy_from_slice(&block.as_slice()[..5]);
            out
        }
    }
}
