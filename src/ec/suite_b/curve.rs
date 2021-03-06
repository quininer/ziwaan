// Copyright 2015-2017 Brian Smith.
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

use crate::{ec, error, rand};

/// A key agreement algorithm.
macro_rules! suite_b_curve {
    ( $NAME:ident, $bits:expr, $id:expr,
      $check_private_key_bytes:ident, $generate_private_key:ident,
      $public_from_private:ident) => {
        /// Public keys are encoding in uncompressed form using the
        /// Octet-String-to-Elliptic-Curve-Point algorithm in
        /// [SEC 1: Elliptic Curve Cryptography, Version 2.0]. Public keys are
        /// validated during key agreement according to
        /// [NIST Special Publication 800-56A, revision 2] and Appendix B.3 of
        /// the NSA's [Suite B Implementer's Guide to NIST SP 800-56A].
        ///
        /// [SEC 1: Elliptic Curve Cryptography, Version 2.0]:
        ///     http://www.secg.org/sec1-v2.pdf
        /// [NIST Special Publication 800-56A, revision 2]:
        ///     http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-56Ar2.pdf
        /// [Suite B Implementer's Guide to NIST SP 800-56A]:
        ///     https://github.com/briansmith/ring/blob/main/doc/ecdh.pdf
        pub static $NAME: ec::Curve = ec::Curve {
            public_key_len: 1 + (2 * (($bits + 7) / 8)),
            elem_scalar_seed_len: ($bits + 7) / 8,
            id: $id,
            check_private_key_bytes: $check_private_key_bytes,
            generate_private_key: $generate_private_key,
            public_from_private: $public_from_private,
        };

    };
}

suite_b_curve!(
    P256,
    256,
    ec::CurveID::P256,
    p256_check_private_key_bytes,
    p256_generate_private_key,
    p256_public_from_private
);

fn p256_check_private_key_bytes(bytes: &[u8]) -> Result<(), error::Unspecified> {
    <elliptic_curve::SecretKey<p256::NistP256>>::from_be_bytes(bytes)
        .map(drop)
        .map_err(|_| error::Unspecified)
}

fn p256_generate_private_key(
    rng: &dyn rand::SecureRandom,
    out: &mut [u8],
) -> Result<(), error::Unspecified> {
    if out.len() < P256.elem_scalar_seed_len {
        return Err(error::Unspecified);
    }

    let mut rng = rand::RngCompat(rng);
    let sk = <elliptic_curve::SecretKey<p256::NistP256>>::random(&mut rng);
    out[..P256.elem_scalar_seed_len].copy_from_slice(sk.to_be_bytes().as_slice());

    Ok(())
}

fn p256_public_from_private(
    public_out: &mut [u8],
    private_key: &ec::Seed,
) -> Result<(), error::Unspecified> {
    use elliptic_curve::sec1::EncodedPoint;

    if public_out.len() < P256.public_key_len {
        return Err(error::Unspecified);
    }

    let private_key =
        <elliptic_curve::SecretKey<p256::NistP256>>::from_be_bytes(&private_key.bytes_less_safe())
            .map_err(|_| error::Unspecified)?;
    let public_key = private_key.public_key();
    let public_key = <EncodedPoint<p256::NistP256>>::from(public_key);

    public_out[..P256.public_key_len].copy_from_slice(public_key.as_bytes());

    Ok(())
}

suite_b_curve!(
    P384,
    384,
    ec::CurveID::P384,
    p384_check_private_key_bytes,
    p384_generate_private_key,
    p384_public_from_private
);

fn p384_check_private_key_bytes(bytes: &[u8]) -> Result<(), error::Unspecified> {
    <elliptic_curve::SecretKey<p384::NistP384>>::from_be_bytes(bytes)
        .map(drop)
        .map_err(|_| error::Unspecified)
}

fn p384_generate_private_key(
    rng: &dyn rand::SecureRandom,
    out: &mut [u8],
) -> Result<(), error::Unspecified> {
    if out.len() < P384.elem_scalar_seed_len {
        return Err(error::Unspecified);
    }

    let mut rng = rand::RngCompat(rng);
    let sk = <elliptic_curve::SecretKey<p384::NistP384>>::random(&mut rng);
    out[..P384.elem_scalar_seed_len].copy_from_slice(sk.to_be_bytes().as_slice());

    Ok(())
}

fn p384_public_from_private(
    public_out: &mut [u8],
    private_key: &ec::Seed,
) -> Result<(), error::Unspecified> {
    use elliptic_curve::sec1::EncodedPoint;

    if public_out.len() < P384.public_key_len {
        return Err(error::Unspecified);
    }

    let private_key =
        <elliptic_curve::SecretKey<p384::NistP384>>::from_be_bytes(&private_key.bytes_less_safe())
            .map_err(|_| error::Unspecified)?;
    let public_key = private_key.public_key();
    let public_key = <EncodedPoint<p384::NistP384>>::from(public_key);

    public_out[..P384.public_key_len].copy_from_slice(public_key.as_bytes());

    Ok(())
}
