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

//! ECDSA Signatures using the P-256 and P-384 curves.

use crate::{
    ec,
    error,
    io::der,
    pkcs8, rand, sealed, signature,
};

/// An ECDSA signing algorithm.
pub struct EcdsaSigningAlgorithm {
    curve: &'static ec::Curve,
    sign: fn(seed: &ec::Seed, rng: &dyn rand::SecureRandom, msg: &[u8])
        -> Result<signature::Signature, error::Unspecified>,
    format_sig: fn(signature::Signature) -> signature::Signature,
    pkcs8_template: &'static pkcs8::Template,
    id: AlgorithmID,
}

#[derive(Debug, Eq, PartialEq)]
enum AlgorithmID {
    ECDSA_P256_SHA256_FIXED_SIGNING,
    ECDSA_P384_SHA384_FIXED_SIGNING,
    ECDSA_P256_SHA256_ASN1_SIGNING,
    ECDSA_P384_SHA384_ASN1_SIGNING,
}

derive_debug_via_id!(EcdsaSigningAlgorithm);

impl PartialEq for EcdsaSigningAlgorithm {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

impl Eq for EcdsaSigningAlgorithm {}

impl sealed::Sealed for EcdsaSigningAlgorithm {}

/// An ECDSA key pair, used for signing.
pub struct EcdsaKeyPair {
    alg: &'static EcdsaSigningAlgorithm,
    seed: ec::Seed,
    public_key: PublicKey,
}

derive_debug_via_field!(EcdsaKeyPair, stringify!(EcdsaKeyPair), public_key);

impl EcdsaKeyPair {
    /// Generates a new key pair and returns the key pair serialized as a
    /// PKCS#8 document.
    ///
    /// The PKCS#8 document will be a v1 `OneAsymmetricKey` with the public key
    /// included in the `ECPrivateKey` structure, as described in
    /// [RFC 5958 Section 2] and [RFC 5915]. The `ECPrivateKey` structure will
    /// not have a `parameters` field so the generated key is compatible with
    /// PKCS#11.
    ///
    /// [RFC 5915]: https://tools.ietf.org/html/rfc5915
    /// [RFC 5958 Section 2]: https://tools.ietf.org/html/rfc5958#section-2
    pub fn generate_pkcs8(
        alg: &'static EcdsaSigningAlgorithm,
        rng: &dyn rand::SecureRandom,
    ) -> Result<pkcs8::Document, error::Unspecified> {
        let private_key = ec::Seed::generate(alg.curve, rng)?;
        let public_key = private_key.compute_public_key()?;
        Ok(pkcs8::wrap_key(
            &alg.pkcs8_template,
            private_key.bytes_less_safe(),
            public_key.as_ref(),
        ))
    }

    /// Constructs an ECDSA key pair by parsing an unencrypted PKCS#8 v1
    /// id-ecPublicKey `ECPrivateKey` key.
    ///
    /// The input must be in PKCS#8 v1 format. It must contain the public key in
    /// the `ECPrivateKey` structure; `from_pkcs8()` will verify that the public
    /// key and the private key are consistent with each other. The algorithm
    /// identifier must identify the curve by name; it must not use an
    /// "explicit" encoding of the curve. The `parameters` field of the
    /// `ECPrivateKey`, if present, must be the same named curve that is in the
    /// algorithm identifier in the PKCS#8 header.
    pub fn from_pkcs8(
        alg: &'static EcdsaSigningAlgorithm,
        pkcs8: &[u8],
    ) -> Result<Self, error::KeyRejected> {
        let key_pair = ec::suite_b::key_pair_from_pkcs8(
            alg.curve,
            alg.pkcs8_template,
            untrusted::Input::from(pkcs8),
        )?;
        let rng = rand::SystemRandom::new(); // TODO: make this a parameter.
        Self::new(alg, key_pair, &rng)
    }

    /// Constructs an ECDSA key pair from the private key and public key bytes
    ///
    /// The private key must encoded as a big-endian fixed-length integer. For
    /// example, a P-256 private key must be 32 bytes prefixed with leading
    /// zeros as needed.
    ///
    /// The public key is encoding in uncompressed form using the
    /// Octet-String-to-Elliptic-Curve-Point algorithm in
    /// [SEC 1: Elliptic Curve Cryptography, Version 2.0].
    ///
    /// This is intended for use by code that deserializes key pairs. It is
    /// recommended to use `EcdsaKeyPair::from_pkcs8()` (with a PKCS#8-encoded
    /// key) instead.
    ///
    /// [SEC 1: Elliptic Curve Cryptography, Version 2.0]:
    ///     http://www.secg.org/sec1-v2.pdf
    pub fn from_private_key_and_public_key(
        alg: &'static EcdsaSigningAlgorithm,
        private_key: &[u8],
        public_key: &[u8],
    ) -> Result<Self, error::KeyRejected> {
        let key_pair = ec::suite_b::key_pair_from_bytes(
            alg.curve,
            untrusted::Input::from(private_key),
            untrusted::Input::from(public_key),
        )?;
        let rng = rand::SystemRandom::new(); // TODO: make this a parameter.
        Self::new(alg, key_pair, &rng)
    }

    fn new(
        alg: &'static EcdsaSigningAlgorithm,
        key_pair: ec::KeyPair,
        rng: &dyn rand::SecureRandom,
    ) -> Result<Self, error::KeyRejected> {
        let (seed, public_key) = key_pair.split();
        let public_key = PublicKey(public_key);
        Ok(Self { alg, seed, public_key })
    }

    /// Deprecated. Returns the signature of the `message` using a random nonce
    /// generated by `rng`.
    pub fn sign(
        &self,
        rng: &dyn rand::SecureRandom,
        message: &[u8],
    ) -> Result<signature::Signature, error::Unspecified> {
        let sig = (self.alg.sign)(&self.seed, rng, message)?;
        let sig = (self.alg.format_sig)(sig);
        Ok(sig)
    }
}

impl signature::KeyPair for EcdsaKeyPair {
    type PublicKey = PublicKey;

    fn public_key(&self) -> &Self::PublicKey {
        &self.public_key
    }
}

#[derive(Clone, Copy)]
pub struct PublicKey(ec::PublicKey);

derive_debug_self_as_ref_hex_bytes!(PublicKey);

impl AsRef<[u8]> for PublicKey {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

/// Signing of fixed-length (PKCS#11 style) ECDSA signatures using the
/// P-256 curve and SHA-256.
///
/// See "`ECDSA_*_FIXED` Details" in `ring::signature`'s module-level
/// documentation for more details.
pub static ECDSA_P256_SHA256_FIXED_SIGNING: EcdsaSigningAlgorithm = EcdsaSigningAlgorithm {
    curve: &ec::suite_b::curve::P256,
    sign: p256_sha256_sign,
    format_sig: format_sig_fixed,
    pkcs8_template: &EC_PUBLIC_KEY_P256_PKCS8_V1_TEMPLATE,
    id: AlgorithmID::ECDSA_P256_SHA256_FIXED_SIGNING,
};

fn p256_sha256_sign(seed: &ec::Seed, rng: &dyn rand::SecureRandom, msg: &[u8])
    -> Result<signature::Signature, error::Unspecified>
{
    use p256::ecdsa::signature::RandomizedSigner;

    let sk = <p256::ecdsa::SigningKey>::from_bytes(seed.bytes_less_safe())
        .map_err(|_| error::Unspecified)?;

    let mut rng = rand::RngCompat(rng);

    for _ in 0..100 {
        if let Ok(sig) = sk.try_sign_with_rng(&mut rng, msg) {
            return Ok(signature::Signature::new(|sig_bytes| {
                let sig = sig.as_ref();
                sig_bytes[..sig.len()].copy_from_slice(sig);
                sig.len()
            }));
        }
    }

    Err(error::Unspecified)
}

fn format_sig_fixed(sig: signature::Signature) -> signature::Signature {
    sig
}

/// Signing of ASN.1 DER-encoded ECDSA signatures using the P-256 curve and
/// SHA-256.
///
/// See "`ECDSA_*_ASN1` Details" in `ring::signature`'s module-level
/// documentation for more details.
pub static ECDSA_P256_SHA256_ASN1_SIGNING: EcdsaSigningAlgorithm = EcdsaSigningAlgorithm {
    curve: &ec::suite_b::curve::P256,
    sign: p256_sha256_sign,
    format_sig: p256_format_sig_asn1,
    pkcs8_template: &EC_PUBLIC_KEY_P256_PKCS8_V1_TEMPLATE,
    id: AlgorithmID::ECDSA_P256_SHA256_ASN1_SIGNING,
};

fn p256_format_sig_asn1(sig: signature::Signature) -> signature::Signature {
    use core::convert::TryInto;

    let sig: p256::ecdsa::Signature = sig.as_ref().try_into().unwrap();
    let sig = sig.to_der();

    signature::Signature::new(|bytes| {
        let sig = sig.as_ref();
        bytes[..sig.len()].copy_from_slice(sig);
        sig.len()
    })
}

/// Signing of fixed-length (PKCS#11 style) ECDSA signatures using the
/// P-384 curve and SHA-384.
///
/// See "`ECDSA_*_FIXED` Details" in `ring::signature`'s module-level
/// documentation for more details.
pub static ECDSA_P384_SHA384_FIXED_SIGNING: EcdsaSigningAlgorithm = EcdsaSigningAlgorithm {
    curve: &ec::suite_b::curve::P384,
    sign: p384_sha384_sign,
    format_sig: format_sig_fixed,
    pkcs8_template: &EC_PUBLIC_KEY_P384_PKCS8_V1_TEMPLATE,
    id: AlgorithmID::ECDSA_P384_SHA384_FIXED_SIGNING,
};

/// Signing of ASN.1 DER-encoded ECDSA signatures using the P-384 curve and
/// SHA-384.
///
/// See "`ECDSA_*_ASN1` Details" in `ring::signature`'s module-level
/// documentation for more details.
pub static ECDSA_P384_SHA384_ASN1_SIGNING: EcdsaSigningAlgorithm = EcdsaSigningAlgorithm {
    curve: &ec::suite_b::curve::P384,
    sign: p384_sha384_sign,
    format_sig: p384_format_sig_asn1,
    pkcs8_template: &EC_PUBLIC_KEY_P384_PKCS8_V1_TEMPLATE,
    id: AlgorithmID::ECDSA_P384_SHA384_ASN1_SIGNING,
};

fn p384_sha384_sign(seed: &ec::Seed, rng: &dyn rand::SecureRandom, msg: &[u8])
    -> Result<signature::Signature, error::Unspecified>
{
    use p384::ecdsa::signature::RandomizedSigner;
    use p384::ecdsa::signature::RandomizedDigestSigner;
    use sha2::Sha384;
    use sha2::Digest;

    let sk = <p384::ecdsa::SigningKey>::from_bytes(seed.bytes_less_safe())
        .map_err(|_| error::Unspecified)?;

    let mut rng = rand::RngCompat(rng);

    for _ in 0..100 {
        if let Ok(sig) = sk.try_sign_digest_with_rng(&mut rng, Sha384::default().chain_update(msg)) {
            return Ok(signature::Signature::new(|sig_bytes| {
                let sig = sig.as_ref();
                sig_bytes[..sig.len()].copy_from_slice(sig);
                sig.len()
            }));
        }
    }

    Err(error::Unspecified)
}

fn p384_format_sig_asn1(sig: signature::Signature) -> signature::Signature {
    use core::convert::TryInto;

    let sig: p384::ecdsa::Signature = sig.as_ref().try_into().unwrap();
    let sig = sig.to_der();

    signature::Signature::new(|bytes| {
        let sig = sig.as_ref();
        bytes[..sig.len()].copy_from_slice(sig);
        sig.len()
    })
}

static EC_PUBLIC_KEY_P256_PKCS8_V1_TEMPLATE: pkcs8::Template = pkcs8::Template {
    bytes: include_bytes!("ecPublicKey_p256_pkcs8_v1_template.der"),
    alg_id_range: core::ops::Range { start: 8, end: 27 },
    curve_id_index: 9,
    private_key_index: 0x24,
};

static EC_PUBLIC_KEY_P384_PKCS8_V1_TEMPLATE: pkcs8::Template = pkcs8::Template {
    bytes: include_bytes!("ecPublicKey_p384_pkcs8_v1_template.der"),
    alg_id_range: core::ops::Range { start: 8, end: 24 },
    curve_id_index: 9,
    private_key_index: 0x23,
};
