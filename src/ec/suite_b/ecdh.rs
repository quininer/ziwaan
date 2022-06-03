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

//! ECDH key agreement using the P-256 and P-384 curves.

use crate::{agreement, ec, error};

/// A key agreement algorithm.
macro_rules! ecdh {
    ( $NAME:ident, $curve:expr, $name_str:expr, $ecdh:ident ) => {
        #[doc = "ECDH using the NSA Suite B"]
        #[doc=$name_str]
        #[doc = "curve."]
        ///
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
        pub static $NAME: agreement::Algorithm = agreement::Algorithm {
            curve: $curve,
            ecdh: $ecdh,
        };
    };
}

ecdh!(
    ECDH_P256,
    &ec::suite_b::curve::P256,
    "P-256 (secp256r1)",
    p256_ecdh
);

fn p256_ecdh(
    out: &mut [u8],
    my_private_key: &ec::Seed,
    peer_public_key: untrusted::Input,
) -> Result<(), error::Unspecified> {
    use elliptic_curve::sec1::{ EncodedPoint, FromEncodedPoint };

    let my_private_key =
        <elliptic_curve::SecretKey<p256::NistP256>>::from_be_bytes(&my_private_key.bytes_less_safe())
            .map_err(|_| error::Unspecified)?;
    let peer_public_key =
        <elliptic_curve::PublicKey<p256::NistP256>>::from_sec1_bytes(peer_public_key.as_slice_less_safe())
            .map_err(|_| error::Unspecified)?;

    let shared_secret = elliptic_curve::ecdh::diffie_hellman(
        my_private_key.to_nonzero_scalar(),
        peer_public_key.as_affine()
    );
    let shared_secret = shared_secret.raw_secret_bytes();
    let secret_len = shared_secret.len();

    if out.len() < secret_len {
        return Err(error::Unspecified);
    }

    out[..secret_len].copy_from_slice(shared_secret.as_slice());

    Ok(())
}

ecdh!(
    ECDH_P384,
    &ec::suite_b::curve::P384,
    "P-384 (secp384r1)",
    p384_ecdh
);

fn p384_ecdh(
    out: &mut [u8],
    my_private_key: &ec::Seed,
    peer_public_key: untrusted::Input,
) -> Result<(), error::Unspecified> {
    use elliptic_curve::sec1::{ EncodedPoint, FromEncodedPoint };

    let my_private_key =
        <elliptic_curve::SecretKey<p384::NistP384>>::from_be_bytes(&my_private_key.bytes_less_safe())
            .map_err(|_| error::Unspecified)?;
    let peer_public_key =
        <elliptic_curve::PublicKey<p384::NistP384>>::from_sec1_bytes(peer_public_key.as_slice_less_safe())
            .map_err(|_| error::Unspecified)?;

    let shared_secret = elliptic_curve::ecdh::diffie_hellman(
        my_private_key.to_nonzero_scalar(),
        peer_public_key.as_affine()
    );
    let shared_secret = shared_secret.raw_secret_bytes();
    let secret_len = shared_secret.len();

    if out.len() < secret_len {
        return Err(error::Unspecified);
    }

    out[..secret_len].copy_from_slice(shared_secret.as_slice());

    Ok(())
}
