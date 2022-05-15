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
    digest,
    error,
    io::der,
    sealed, signature,
};
use openssl::hash::MessageDigest;
use openssl::ec::EcGroupRef;

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
    parse_format: p256_sig_fixed_parse,
    id: AlgorithmID::ECDSA_P256_SHA256_FIXED,
};

/// Verification of ASN.1 DER-encoded ECDSA signatures using the P-256 curve
/// and SHA-256.
///
/// See "`ECDSA_*_ASN1` Details" in `ring::signature`'s module-level
/// documentation for more details.
pub static ECDSA_P256_SHA256_ASN1: EcdsaVerificationAlgorithm = EcdsaVerificationAlgorithm {
    verify: p256_sha256_verify,
    parse_format: sig_asn1_parse,
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
    parse_format: sig_asn1_parse,
    id: AlgorithmID::ECDSA_P256_SHA384_ASN1,
};

fn verify(group: &EcGroupRef, public_key: &[u8], hash: MessageDigest, msg: &[u8], sig: &signature::Signature)
    -> Result<(), error::Unspecified>
{
    use openssl::ec::EcKey;
    use openssl::pkey::PKey;
    use openssl::sign::Verifier;

    dbg!();

    let public_key = {
        let mut ctx = openssl::bn::BigNumContext::new()
            .map_err(|_| error::Unspecified)?;
        let point = openssl::ec::EcPoint::from_bytes(group, public_key, &mut ctx)
            .map_err(|_| error::Unspecified)?;
        let public_key = EcKey::from_public_key(&group, &point)
            .map_err(|_| error::Unspecified)?;
        PKey::from_ec_key(public_key).map_err(|_| error::Unspecified)?
    };
    dbg!();

    let mut verifier = Verifier::new(hash, &public_key)
        .map_err(|_| error::Unspecified)?;

    dbg!();
    let ret = dbg!(verifier.verify_oneshot(sig.as_ref(), msg))
        .map_err(|_| error::Unspecified)?;

    dbg!();
    if ret {
        Ok(())
    } else {
        Err(error::Unspecified)
    }
}

fn p256_sha256_verify(public_key: &[u8], msg: &[u8], sig: &signature::Signature)
    -> Result<(), error::Unspecified>
{
    // secp256r1
    let group = openssl::ec::EcGroup::from_curve_name(openssl::nid::Nid::X9_62_PRIME256V1).unwrap();
    verify(&group, public_key, MessageDigest::sha256(), msg, sig)
}

fn p256_sha384_verify(public_key: &[u8], msg: &[u8], sig: &signature::Signature)
    -> Result<(), error::Unspecified>
{
    // secp256r1
    let group = openssl::ec::EcGroup::from_curve_name(openssl::nid::Nid::X9_62_PRIME256V1).unwrap();
    verify(&group, public_key, MessageDigest::sha384(), msg, sig)
}

fn sig_fixed_parse(scalar_len: usize, sig: &[u8]) -> Result<signature::Signature, error::Unspecified> {
    use openssl::ecdsa::EcdsaSig;
    use openssl::bn::BigNum;

    if sig.len() != scalar_len * 2 {
        return Err(error::Unspecified);
    }

    let (r, s) = sig.split_at(scalar_len);
    let r = BigNum::from_slice(r).map_err(|_| error::Unspecified)?;
    let s = BigNum::from_slice(s).map_err(|_| error::Unspecified)?;

    let sig = EcdsaSig::from_private_components(r, s).map_err(|_| error::Unspecified)?;
    let sig = sig.to_der().map_err(|_| error::Unspecified)?;

    signature::Signature::try_new(|bytes| {
        if bytes.len() >= sig.len() {
            bytes[..sig.len()].copy_from_slice(&sig);
            Ok(sig.len())
        } else {
            Err(error::Unspecified)
        }
    })
}

fn p256_sig_fixed_parse(sig: &[u8]) -> Result<signature::Signature, error::Unspecified> {
    let scalar_len = ec::suite_b::curve::P256.elem_scalar_seed_len;
    sig_fixed_parse(scalar_len, sig)
}

fn sig_asn1_parse(sig: &[u8]) -> Result<signature::Signature, error::Unspecified> {
    signature::Signature::try_new(|bytes| {
        if bytes.len() >= sig.len() {
            bytes[..sig.len()].copy_from_slice(&sig);
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
    parse_format: p384_sig_fixed_parse,
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
    verify: p384_sha256_verify,
    parse_format: sig_asn1_parse,
    id: AlgorithmID::ECDSA_P384_SHA256_ASN1,
};

/// Verification of ASN.1 DER-encoded ECDSA signatures using the P-384 curve
/// and SHA-384.
///
/// See "`ECDSA_*_ASN1` Details" in `ring::signature`'s module-level
/// documentation for more details.
pub static ECDSA_P384_SHA384_ASN1: EcdsaVerificationAlgorithm = EcdsaVerificationAlgorithm {
    verify: p384_sha384_verify,
    parse_format: sig_asn1_parse,
    id: AlgorithmID::ECDSA_P384_SHA384_ASN1,
};

fn p384_sha256_verify(public_key: &[u8], msg: &[u8], sig: &signature::Signature)
    -> Result<(), error::Unspecified>
{
    // secp384r1
    let group = openssl::ec::EcGroup::from_curve_name(openssl::nid::Nid::SECP384R1).unwrap();
    verify(&group, public_key, MessageDigest::sha256(), msg, sig)
}


fn p384_sha384_verify(public_key: &[u8], msg: &[u8], sig: &signature::Signature)
    -> Result<(), error::Unspecified>
{
    // secp384r1
    let group = openssl::ec::EcGroup::from_curve_name(openssl::nid::Nid::SECP384R1).unwrap();
    verify(&group, public_key, MessageDigest::sha384(), msg, sig)
}

fn p384_sig_fixed_parse(sig: &[u8]) -> Result<signature::Signature, error::Unspecified> {
    let scalar_len = ec::suite_b::curve::P384.elem_scalar_seed_len;
    sig_fixed_parse(scalar_len, sig)
}
