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

//! X25519 Key agreement.

use crate::{agreement, constant_time, ec, error, rand};
use core::convert::TryInto;

static CURVE25519: ec::Curve = ec::Curve {
    public_key_len: PUBLIC_KEY_LEN,
    elem_scalar_seed_len: ELEM_AND_SCALAR_LEN,
    id: ec::CurveID::Curve25519,
    check_private_key_bytes: x25519_check_private_key_bytes,
    generate_private_key: x25519_generate_private_key,
    public_from_private: x25519_public_from_private,
};

const SCALAR_LEN: usize = 32;

/// X25519 (ECDH using Curve25519) as described in [RFC 7748].
///
/// Everything is as described in RFC 7748. Key agreement will fail if the
/// result of the X25519 operation is zero; see the notes on the
/// "all-zero value" in [RFC 7748 section 6.1].
///
/// [RFC 7748]: https://tools.ietf.org/html/rfc7748
/// [RFC 7748 section 6.1]: https://tools.ietf.org/html/rfc7748#section-6.1
pub static X25519: agreement::Algorithm = agreement::Algorithm {
    curve: &CURVE25519,
    ecdh: x25519_ecdh,
};

fn x25519_check_private_key_bytes(bytes: &[u8]) -> Result<(), error::Unspecified> {
    debug_assert_eq!(bytes.len(), PRIVATE_KEY_LEN);
    Ok(())
}

fn x25519_generate_private_key(
    rng: &dyn rand::SecureRandom,
    out: &mut [u8],
) -> Result<(), error::Unspecified> {
    rng.fill(out)
}

fn x25519_public_from_private(
    public_out: &mut [u8],
    private_key: &ec::Seed,
) -> Result<(), error::Unspecified> {
    let public_out: &mut [u8; PUBLIC_KEY_LEN] = public_out.try_into()?;

    let private_key: [u8; SCALAR_LEN] = private_key.bytes_less_safe().try_into()?;
    let private_key = x25519_dalek::StaticSecret::from(private_key);

    let public_key = x25519_dalek::PublicKey::from(&private_key);

    public_out.copy_from_slice(public_key.as_bytes());

    Ok(())
}

fn x25519_ecdh(
    out: &mut [u8],
    my_private_key: &ec::Seed,
    peer_public_key: untrusted::Input,
) -> Result<(), error::Unspecified> {
    let out: &mut [u8; SHARED_SECRET_LEN] = out.try_into()?;

    let my_private_key: [u8; SCALAR_LEN] = my_private_key.bytes_less_safe().try_into()?;
    let my_private_key = x25519_dalek::StaticSecret::from(my_private_key);
    let peer_public_key: [u8; PUBLIC_KEY_LEN] = peer_public_key.as_slice_less_safe().try_into()?;
    let peer_public_key = x25519_dalek::PublicKey::from(peer_public_key);

    let shared_secret = my_private_key.diffie_hellman(&peer_public_key);

    let zeros = [0; SHARED_SECRET_LEN];
    if constant_time::verify_slices_are_equal(shared_secret.as_bytes(), &zeros).is_ok() {
        // All-zero output results when the input is a point of small order.
        return Err(error::Unspecified);
    }

    out.copy_from_slice(shared_secret.as_bytes());

    Ok(())
}

const ELEM_AND_SCALAR_LEN: usize = 32;
const PRIVATE_KEY_LEN: usize = ELEM_AND_SCALAR_LEN;
const PUBLIC_KEY_LEN: usize = ELEM_AND_SCALAR_LEN;
const SHARED_SECRET_LEN: usize = ELEM_AND_SCALAR_LEN;
