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
use chacha20poly1305::ChaCha20Poly1305;
use chacha20poly1305::aead::{ self, NewAead, AeadInPlace };
use chacha20poly1305::aead::generic_array::typenum::Unsigned;

/// ChaCha20-Poly1305 as described in [RFC 7539].
///
/// The keys are 256 bits long and the nonces are 96 bits long.
///
/// [RFC 7539]: https://tools.ietf.org/html/rfc7539
pub static CHACHA20_POLY1305: Algorithm = Algorithm {
    key_len: KEY_LEN,
    init: chacha20_poly1305_init,
    seal: chacha20_poly1305_seal,
    open: chacha20_poly1305_open,
    id: AlgorithmID::CHACHA20_POLY1305,
    max_input_len: super::max_input_len(64, 1),
};

const KEY_LEN: usize = <<ChaCha20Poly1305 as aead::NewAead>::KeySize as Unsigned>::USIZE;

/// Copies |key| into |ctx_buf|.
fn chacha20_poly1305_init(
    key: &[u8],
) -> Result<KeyInner, error::Unspecified> {
    let key: [u8; KEY_LEN] = key.try_into()?;
    Ok(KeyInner::ChaCha20Poly1305(Key::from(key)))
}

fn chacha20_poly1305_seal(
    key: &KeyInner,
    nonce: Nonce,
    Aad(aad): Aad<&[u8]>,
    in_out: &mut [u8],
) -> Result<Tag, error::Unspecified> {
    let key = match key {
        KeyInner::ChaCha20Poly1305(key) => key,
        _ => unreachable!(),
    };

    let cipher = ChaCha20Poly1305::new(key);
    let nonce = <aead::Nonce<ChaCha20Poly1305>>::from(*nonce.as_ref());

    cipher.encrypt_in_place_detached(&nonce, aad, in_out)
        .map(|tag| Tag(tag.into()))
        .map_err(|_| error::Unspecified)
}

fn chacha20_poly1305_open(
    key: &KeyInner,
    nonce: Nonce,
    Aad(aad): Aad<&[u8]>,
    in_prefix_len: usize,
    in_out: &mut [u8],
    tag: &Tag
) -> Result<(), error::Unspecified> {
    let key = match key {
        KeyInner::ChaCha20Poly1305(key) => key,
        _ => unreachable!(),
    };

    let cipher = ChaCha20Poly1305::new(key);
    let nonce = <aead::Nonce<ChaCha20Poly1305>>::from(*nonce.as_ref());
    let tag = <aead::Tag<ChaCha20Poly1305>>::from(tag.0);

    cipher.decrypt_in_place_detached(&nonce, aad, &mut in_out[in_prefix_len..], &tag)
        .map_err(|_| error::Unspecified)
}

pub type Key = chacha20poly1305::Key;

#[cfg(test)]
mod tests {
    #[test]
    fn max_input_len_test() {
        // Errata 4858 at https://www.rfc-editor.org/errata_search.php?rfc=7539.
        assert_eq!(super::CHACHA20_POLY1305.max_input_len, 274_877_906_880u64);
    }
}
