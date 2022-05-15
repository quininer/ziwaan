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
    digest,
    error,
    io::der,
    sealed, signature,
};

/// An ECDSA verification algorithm.
pub struct EcdsaVerificationAlgorithm {
    verify: fn(public_key: &[u8], msg: &[u8], sig: &signature::Signature)
        -> Result<(), error::Unspecified>,
    parse_format: fn(sig: &[u8])
        -> Result<signature::Signature, error::Unspecified>,
    id: AlgorithmID,
}

#[derive(Debug)]
enum AlgorithmID {
    ECDSA_P256_SHA256_ASN1,
    ECDSA_P256_SHA256_FIXED,
    ECDSA_P256_SHA384_ASN1,
    ECDSA_P384_SHA256_ASN1,
    ECDSA_P384_SHA384_ASN1,
    ECDSA_P384_SHA384_FIXED,
}

derive_debug_via_id!(EcdsaVerificationAlgorithm);

impl signature::VerificationAlgorithm for EcdsaVerificationAlgorithm {
    fn verify(
        &self,
        public_key: untrusted::Input,
        msg: untrusted::Input,
        signature: untrusted::Input,
    ) -> Result<(), error::Unspecified> {
        let sig = (self.parse_format)(signature.as_slice_less_safe())?;
        (self.verify)(
            public_key.as_slice_less_safe(),
            msg.as_slice_less_safe(),
            &sig
        )
    }
}

impl sealed::Sealed for EcdsaVerificationAlgorithm {}

/// Verification of fixed-length (PKCS#11 style) ECDSA signatures using the
/// P-256 curve and SHA-256.
///
/// See "`ECDSA_*_FIXED` Details" in `ring::signature`'s module-level
/// documentation for more details.
pub static ECDSA_P256_SHA256_FIXED: EcdsaVerificationAlgorithm = EcdsaVerificationAlgorithm {
    verify: p256_sha256_verify,
    parse_format: sig_fixed_parse,
    id: AlgorithmID::ECDSA_P256_SHA256_FIXED,
};

/// Verification of ASN.1 DER-encoded ECDSA signatures using the P-256 curve
/// and SHA-256.
///
/// See "`ECDSA_*_ASN1` Details" in `ring::signature`'s module-level
/// documentation for more details.
pub static ECDSA_P256_SHA256_ASN1: EcdsaVerificationAlgorithm = EcdsaVerificationAlgorithm {
    verify: p256_sha256_verify,
    parse_format: p256_sig_asn1_parse,
    id: AlgorithmID::ECDSA_P256_SHA256_ASN1,
};

/// *Not recommended*. Verification of ASN.1 DER-encoded ECDSA signatures using
/// the P-256 curve and SHA-384.
///
/// In most situations, P-256 should be used only with SHA-256 and P-384
/// should be used only with SHA-384. However, in some cases, particularly TLS
/// on the web, it is necessary to support P-256 with SHA-384 for compatibility
/// with widely-deployed implementations that do not follow these guidelines.
///
/// See "`ECDSA_*_ASN1` Details" in `ring::signature`'s module-level
/// documentation for more details.
pub static ECDSA_P256_SHA384_ASN1: EcdsaVerificationAlgorithm = EcdsaVerificationAlgorithm {
    verify: p256_sha384_verify,
    parse_format: p256_sig_asn1_parse,
    id: AlgorithmID::ECDSA_P256_SHA384_ASN1,
};

fn p256_sha256_verify(public_key: &[u8], msg: &[u8], sig: &signature::Signature)
    -> Result<(), error::Unspecified>
{
    use p256::ecdsa::signature::{ DigestVerifier, Signature as _ };
    use sha2::{ Digest, Sha256 };

    let peer_public_key =
        <p256::ecdsa::VerifyingKey>::from_sec1_bytes(public_key)
            .map_err(|_| error::Unspecified)?;
    let sig = <p256::ecdsa::Signature>::from_bytes(sig.as_ref())
        .map_err(|_| error::Unspecified)?;

    peer_public_key.verify_digest(Sha256::new().chain_update(msg), &sig)
        .map_err(|_| error::Unspecified)
}

fn p256_sha384_verify(public_key: &[u8], msg: &[u8], sig: &signature::Signature)
    -> Result<(), error::Unspecified>
{
    use p256::ecdsa::signature::{ DigestVerifier, Signature as _ };
    use sha2::{ digest::{ self, Digest }, Sha384 };
    use sha2::digest::generic_array::GenericArray;

    #[derive(Clone, Default)]
    struct Sha384_256(Sha384);

    impl digest::HashMarker for Sha384_256 {}

    impl digest::OutputSizeUser for Sha384_256 {
        type OutputSize = digest::consts::U32;
    }

    impl digest::Update for Sha384_256 {
        fn update(&mut self, data: &[u8]) {
            digest::Update::update(&mut self.0, data);
        }
    }

    impl digest::FixedOutput for Sha384_256 {
        fn finalize_into(self, out: &mut GenericArray<u8, Self::OutputSize>) {
            let output = self.0.finalize();
            out.copy_from_slice(&output[..32]);
        }
    }

    impl digest::Reset for Sha384_256 {
        fn reset(&mut self) {
            digest::Reset::reset(&mut self.0);
        }
    }

    let peer_public_key =
        <p256::ecdsa::VerifyingKey>::from_sec1_bytes(public_key)
            .map_err(|_| error::Unspecified)?;
    let sig = <p256::ecdsa::Signature>::from_bytes(sig.as_ref())
        .map_err(|_| error::Unspecified)?;

    peer_public_key.verify_digest(Sha384_256(Sha384::new()).chain_update(msg), &sig)
        .map_err(|_| error::Unspecified)
}

fn sig_fixed_parse(sig: &[u8]) -> Result<signature::Signature, error::Unspecified> {
    signature::Signature::try_new(|bytes| {
        if bytes.len() >= sig.len() {
            bytes[..sig.len()].copy_from_slice(sig);
            Ok(sig.len())
        } else {
            Err(error::Unspecified)
        }
    })
}

fn p256_sig_asn1_parse(sig: &[u8]) -> Result<signature::Signature, error::Unspecified> {
    let sig = <p256::ecdsa::Signature>::from_der(sig)
        .map_err(|_| error::Unspecified)?;
    let sig = sig.as_ref();

    signature::Signature::try_new(|bytes| {
        if bytes.len() >= sig.len() {
            bytes[..sig.len()].copy_from_slice(sig);
            Ok(sig.len())
        } else {
            Err(error::Unspecified)
        }
    })
}

/// Verification of fixed-length (PKCS#11 style) ECDSA signatures using the
/// P-384 curve and SHA-384.
///
/// See "`ECDSA_*_FIXED` Details" in `ring::signature`'s module-level
/// documentation for more details.
pub static ECDSA_P384_SHA384_FIXED: EcdsaVerificationAlgorithm = EcdsaVerificationAlgorithm {
    verify: p384_sha384_verify,
    parse_format: sig_fixed_parse,
    id: AlgorithmID::ECDSA_P384_SHA384_FIXED,
};

/// *Not recommended*. Verification of ASN.1 DER-encoded ECDSA signatures using
/// the P-384 curve and SHA-256.
///
/// In most situations, P-256 should be used only with SHA-256 and P-384
/// should be used only with SHA-384. However, in some cases, particularly TLS
/// on the web, it is necessary to support P-256 with SHA-384 for compatibility
/// with widely-deployed implementations that do not follow these guidelines.
///
/// See "`ECDSA_*_ASN1` Details" in `ring::signature`'s module-level
/// documentation for more details.
pub static ECDSA_P384_SHA256_ASN1: EcdsaVerificationAlgorithm = EcdsaVerificationAlgorithm {
    verify: p384_sha384_verify,
    parse_format: p384_sig_asn1_parse,
    id: AlgorithmID::ECDSA_P384_SHA256_ASN1,
};

/// Verification of ASN.1 DER-encoded ECDSA signatures using the P-384 curve
/// and SHA-384.
///
/// See "`ECDSA_*_ASN1` Details" in `ring::signature`'s module-level
/// documentation for more details.
pub static ECDSA_P384_SHA384_ASN1: EcdsaVerificationAlgorithm = EcdsaVerificationAlgorithm {
    verify: p384_sha384_verify,
    parse_format: p384_sig_asn1_parse,
    id: AlgorithmID::ECDSA_P384_SHA384_ASN1,
};

fn p384_sha384_verify(public_key: &[u8], msg: &[u8], sig: &signature::Signature)
    -> Result<(), error::Unspecified>
{
    use p384::ecdsa::signature::{ DigestVerifier, Signature as _ };
    use sha2::{ Digest, Sha384 };

    let peer_public_key =
        <p384::ecdsa::VerifyingKey>::from_sec1_bytes(public_key)
            .map_err(|_| error::Unspecified)?;
    let sig = <p384::ecdsa::Signature>::from_bytes(sig.as_ref())
        .map_err(|_| error::Unspecified)?;

    peer_public_key.verify_digest(Sha384::new().chain_update(msg), &sig)
        .map_err(|_| error::Unspecified)
}

fn p384_sig_asn1_parse(sig: &[u8]) -> Result<signature::Signature, error::Unspecified> {
    let sig = <p384::ecdsa::Signature>::from_der(sig)
        .map_err(|_| error::Unspecified)?;
    let sig = sig.as_ref();

    signature::Signature::try_new(|bytes| {
        if bytes.len() >= sig.len() {
            bytes[..sig.len()].copy_from_slice(sig);
            Ok(sig.len())
        } else {
            Err(error::Unspecified)
        }
    })
}
