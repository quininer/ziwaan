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
    if bytes.len() != P256.elem_scalar_seed_len {
        return Err(error::Unspecified);
    }

    check_private_key_bytes(bytes)
}

fn p256_generate_private_key(
    rng: &dyn rand::SecureRandom,
    out: &mut [u8],
) -> Result<(), error::Unspecified> {
    generate_private_key(
        P256.elem_scalar_seed_len,
        rng,
        out,
        check_private_key_bytes
    )
}

fn p256_public_from_private(
    public_out: &mut [u8],
    private_key: &ec::Seed,
) -> Result<(), error::Unspecified> {
    // secp256r1
    let group = openssl::ec::EcGroup::from_curve_name(openssl::nid::Nid::X9_62_PRIME256V1).unwrap();

    public_from_private(
        &group,
        P256.public_key_len,
        public_out,
        private_key
    )
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
    if bytes.len() != P384.elem_scalar_seed_len {
        return Err(error::Unspecified);
    }

    check_private_key_bytes(bytes)
}

fn p384_generate_private_key(
    rng: &dyn rand::SecureRandom,
    out: &mut [u8],
) -> Result<(), error::Unspecified> {
    generate_private_key(
        P384.elem_scalar_seed_len,
        rng,
        out,
        check_private_key_bytes
    )
}

fn p384_public_from_private(
    public_out: &mut [u8],
    private_key: &ec::Seed,
) -> Result<(), error::Unspecified> {
    // secp384r1
    let group = openssl::ec::EcGroup::from_curve_name(openssl::nid::Nid::SECP384R1).unwrap();

    public_from_private(
        &group,
        P384.public_key_len,
        public_out,
        private_key
    )
}

fn check_private_key_bytes(bytes: &[u8]) -> Result<(), error::Unspecified> {
    let private_key = openssl::bn::BigNum::from_slice(bytes).map_err(|_| error::Unspecified)?;
    let zero = openssl::bn::BigNum::from_u32(0).map_err(|_| error::Unspecified)?;

    if private_key == zero {
        return Err(error::Unspecified);
    }

    Ok(())
}

fn generate_private_key(
    elem_scalar_seed_len: usize,
    rng: &dyn rand::SecureRandom,
    out: &mut [u8],
    check: fn(&[u8]) -> Result<(), error::Unspecified>
) -> Result<(), error::Unspecified> {
    if out.len() < elem_scalar_seed_len {
        return Err(error::Unspecified);
    }

    for _ in 0..100 {
        rng.fill(out)?;

        if check(out).is_ok() {
            return Ok(())
        }
    }

    Err(error::Unspecified)
}

fn public_from_private(
    group: &openssl::ec::EcGroup,
    public_key_len: usize,
    public_out: &mut [u8],
    private_key: &ec::Seed,
) -> Result<(), error::Unspecified> {
    if public_out.len() < public_key_len {
        return Err(error::Unspecified);
    }

    let private_key = openssl::bn::BigNum::from_slice(private_key.bytes_less_safe())
        .map_err(|_| error::Unspecified)?;

    let mut point = openssl::ec::EcPoint::new(&group).map_err(|_| error::Unspecified)?;
    let mut ctx = openssl::bn::BigNumContext::new().map_err(|_| error::Unspecified)?;

    point.mul_generator(&group, &private_key, &ctx)
        .map_err(|_| error::Unspecified)?;

    let buf = point.to_bytes(&group, openssl::ec::PointConversionForm::UNCOMPRESSED, &mut ctx)
        .map_err(|_| error::Unspecified)?;

    if buf.len() != public_key_len {
        return Err(error::Unspecified);
    }

    public_out[..public_key_len].copy_from_slice(&buf);

    Ok(())
}
