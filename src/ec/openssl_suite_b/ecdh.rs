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
    ( $NAME:ident, $curve:expr, $name_str:expr, $private_key_ops:expr,
      $public_key_ops:expr, $ecdh:ident ) => {
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
    }
}

ecdh!(
    ECDH_P256,
    &ec::suite_b::curve::P256,
    "P-256 (secp256r1)",
    &p256::PRIVATE_KEY_OPS,
    &p256::PUBLIC_KEY_OPS,
    p256_ecdh
);

ecdh!(
    ECDH_P384,
    &ec::suite_b::curve::P384,
    "P-384 (secp384r1)",
    &p384::PRIVATE_KEY_OPS,
    &p384::PUBLIC_KEY_OPS,
    p384_ecdh
);

fn p256_ecdh(
    out: &mut [u8],
    my_private_key: &ec::Seed,
    peer_public_key: untrusted::Input,
) -> Result<(), error::Unspecified> {
    // secp256r1
    let group = openssl::ec::EcGroup::from_curve_name(openssl::nid::Nid::X9_62_PRIME256V1).unwrap();

    ecdh(&group, out, my_private_key, peer_public_key)
}


fn p384_ecdh(
    out: &mut [u8],
    my_private_key: &ec::Seed,
    peer_public_key: untrusted::Input,
) -> Result<(), error::Unspecified> {
    // secp384r1
    let group = openssl::ec::EcGroup::from_curve_name(openssl::nid::Nid::SECP384R1).unwrap();

    ecdh(&group, out, my_private_key, peer_public_key)
}

fn ecdh(
    group: &openssl::ec::EcGroupRef,
    out: &mut [u8],
    my_private_key: &ec::Seed,
    peer_public_key: untrusted::Input,
) -> Result<(), error::Unspecified> {
    use crate::ec::suite_b::private_key::PrivateKey as EcPrivateKey;

    let my_private_key = openssl::bn::BigNum::from_slice(&my_private_key.bytes_less_safe())
        .map_err(|_| error::Unspecified)?;

    let peer_public_key = {
        let mut ctx = openssl::bn::BigNumContext::new()
            .map_err(|_| error::Unspecified)?;
        let ec_point = openssl::ec::EcPoint::from_bytes(
            &group,
            peer_public_key.as_slice_less_safe(),
            &mut ctx
        )
            .map_err(|_| error::Unspecified)?;
        let peer_pk = openssl::ec::EcKey::from_public_key(&group, &ec_point)
            .map_err(|_| error::Unspecified)?;
        openssl::pkey::PKey::from_ec_key(peer_pk).map_err(|_| error::Unspecified)?
    };

    let my_private_key = EcPrivateKey::from_private_key_bignum(&group, &my_private_key)?;
    my_private_key.ecdh(&peer_public_key, out)?;

    Ok(())
}
