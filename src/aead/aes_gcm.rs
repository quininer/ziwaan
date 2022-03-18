// Copyright 2015-2016 Brian Smith.
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

use super::{ Aad, Nonce, Tag, BLOCK_LEN };
use crate::error;
use crate::aead::{ KeyInner, Algorithm, AlgorithmID };
use core::convert::TryInto;
use aes_gcm::{ Aes128Gcm, Aes256Gcm };
use aes_gcm::aead::{ self, NewAead, AeadInPlace };
use aes_gcm::aead::generic_array::typenum::Unsigned;

/// AES-128 in GCM mode with 128-bit tags and 96 bit nonces.
pub static AES_128_GCM: Algorithm = Algorithm {
    key_len: AES_128_KEY_LEN,
    init: init_128,
    seal: aes_gcm_seal,
    open: aes_gcm_open,
    id: AlgorithmID::AES_128_GCM,
    max_input_len: AES_GCM_MAX_INPUT_LEN,
};

/// AES-256 in GCM mode with 128-bit tags and 96 bit nonces.
pub static AES_256_GCM: Algorithm = Algorithm {
    key_len: AES_128_KEY_LEN,
    init: init_256,
    seal: aes_gcm_seal,
    open: aes_gcm_open,
    id: AlgorithmID::AES_256_GCM,
    max_input_len: AES_GCM_MAX_INPUT_LEN,
};

pub enum Key {
    Aes128(Aes128Gcm),
    Aes256(Aes256Gcm)
}

const AES_128_KEY_LEN: usize = <<Aes128Gcm as aead::NewAead>::KeySize as Unsigned>::USIZE;
const AES_256_KEY_LEN: usize = <<Aes256Gcm as aead::NewAead>::KeySize as Unsigned>::USIZE;

fn init_128(key: &[u8]) -> Result<KeyInner, error::Unspecified> {
    let key: &[u8; AES_128_KEY_LEN] = key.try_into()?;
    let key = aes_gcm::Key::from_slice(key);
    Ok(KeyInner::AesGcm(Key::Aes128(Aes128Gcm::new(key))))
}

fn init_256(key: &[u8]) -> Result<KeyInner, error::Unspecified> {
    let key: &[u8; AES_256_KEY_LEN] = key.try_into()?;
    let key = aes_gcm::Key::from_slice(key);
    Ok(KeyInner::AesGcm(Key::Aes256(Aes256Gcm::new(key))))
}

const CHUNK_BLOCKS: usize = 3 * 1024 / 16;

fn aes_gcm_seal(
    key: &KeyInner,
    nonce: Nonce,
    Aad(aad): Aad<&[u8]>,
    in_out: &mut [u8],
) -> Result<Tag, error::Unspecified> {
    match key {
        KeyInner::AesGcm(Key::Aes128(cipher)) => {
            let nonce = <aead::Nonce<Aes128Gcm>>::from(*nonce.as_ref());

            cipher.encrypt_in_place_detached(&nonce, aad, in_out)
                .map(|tag| Tag(tag.into()))
                .map_err(|_| error::Unspecified)
        },
        KeyInner::AesGcm(Key::Aes256(cipher)) => {
            let nonce = <aead::Nonce<Aes256Gcm>>::from(*nonce.as_ref());

            cipher.encrypt_in_place_detached(&nonce, aad, in_out)
                .map(|tag| Tag(tag.into()))
                .map_err(|_| error::Unspecified)
        },
        _ => unreachable!()
    }
}

fn aes_gcm_open(
    key: &KeyInner,
    nonce: Nonce,
    Aad(aad): Aad<&[u8]>,
    in_prefix_len: usize,
    in_out: &mut [u8],
    tag: &Tag
) -> Result<(), error::Unspecified> {
    match key {
        KeyInner::AesGcm(Key::Aes128(cipher)) => {
            let nonce = <aead::Nonce<Aes128Gcm>>::from(*nonce.as_ref());
            let tag = <aead::Tag<Aes128Gcm>>::from(tag.0);

            cipher.decrypt_in_place_detached(&nonce, aad, &mut in_out[in_prefix_len..], &tag)
                .map_err(|_| error::Unspecified)
        },
        KeyInner::AesGcm(Key::Aes256(cipher)) => {
            let nonce = <aead::Nonce<Aes256Gcm>>::from(*nonce.as_ref());
            let tag = <aead::Tag<Aes256Gcm>>::from(tag.0);

            cipher.decrypt_in_place_detached(&nonce, aad, &mut in_out[in_prefix_len..], &tag)
                .map_err(|_| error::Unspecified)
        },
        _ => unreachable!()
    }
}

const AES_GCM_MAX_INPUT_LEN: u64 = super::max_input_len(BLOCK_LEN, 2);

#[cfg(test)]
mod tests {
    #[test]
    fn max_input_len_test() {
        // [NIST SP800-38D] Section 5.2.1.1. Note that [RFC 5116 Section 5.1] and
        // [RFC 5116 Section 5.2] have an off-by-one error in `P_MAX`.
        //
        // [NIST SP800-38D]:
        //    http://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf
        // [RFC 5116 Section 5.1]: https://tools.ietf.org/html/rfc5116#section-5.1
        // [RFC 5116 Section 5.2]: https://tools.ietf.org/html/rfc5116#section-5.2
        const NIST_SP800_38D_MAX_BITS: u64 = (1u64 << 39) - 256;
        assert_eq!(NIST_SP800_38D_MAX_BITS, 549_755_813_632u64);
        assert_eq!(
            super::AES_128_GCM.max_input_len * 8,
            NIST_SP800_38D_MAX_BITS
        );
        assert_eq!(
            super::AES_256_GCM.max_input_len * 8,
            NIST_SP800_38D_MAX_BITS
        );
    }
}
