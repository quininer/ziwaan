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

//! Verification of RSA signatures.

use super::RsaParameters;
use crate::{
    bits, digest, error,
    sealed, signature,
};
use openssl::pkey;

impl signature::VerificationAlgorithm for RsaParameters {
    fn verify(
        &self,
        public_key: untrusted::Input,
        msg: untrusted::Input,
        signature: untrusted::Input,
    ) -> Result<(), error::Unspecified> {
        let public_key = openssl::rsa::Rsa::public_key_from_der_pkcs1(public_key.as_slice_less_safe())
                .map_err(|_| error::Unspecified)?;

        verify(
            self,
            public_key,
            msg.as_slice_less_safe(),
            signature.as_slice_less_safe()
        )
    }
}

impl sealed::Sealed for RsaParameters {}

macro_rules! rsa_params {
    ( $VERIFY_ALGORITHM:ident, $min_bits:expr, $PADDING_ALGORITHM:expr,
      $doc_str:expr ) => {
        #[doc=$doc_str]
        ///
        /// Only available in `alloc` mode.
        pub static $VERIFY_ALGORITHM: RsaParameters = RsaParameters {
            padding_alg: $PADDING_ALGORITHM,
            min_bits: $min_bits
        };
    };
}

rsa_params!(
    RSA_PKCS1_1024_8192_SHA1_FOR_LEGACY_USE_ONLY,
    1024,
    &super::padding::RSA_PKCS1_SHA1_FOR_LEGACY_USE_ONLY,
    "Verification of signatures using RSA keys of 1024-8192 bits,
             PKCS#1.5 padding, and SHA-1.\n\nSee \"`RSA_PKCS1_*` Details\" in
             `ring::signature`'s module-level documentation for more details."
);
rsa_params!(
    RSA_PKCS1_2048_8192_SHA1_FOR_LEGACY_USE_ONLY,
    2048,
    &super::padding::RSA_PKCS1_SHA1_FOR_LEGACY_USE_ONLY,
    "Verification of signatures using RSA keys of 2048-8192 bits,
             PKCS#1.5 padding, and SHA-1.\n\nSee \"`RSA_PKCS1_*` Details\" in
             `ring::signature`'s module-level documentation for more details."
);
rsa_params!(
    RSA_PKCS1_1024_8192_SHA256_FOR_LEGACY_USE_ONLY,
    1024,
    &super::RSA_PKCS1_SHA256,
    "Verification of signatures using RSA keys of 1024-8192 bits,
             PKCS#1.5 padding, and SHA-256.\n\nSee \"`RSA_PKCS1_*` Details\" in
             `ring::signature`'s module-level documentation for more details."
);
rsa_params!(
    RSA_PKCS1_2048_8192_SHA256,
    2048,
    &super::RSA_PKCS1_SHA256,
    "Verification of signatures using RSA keys of 2048-8192 bits,
             PKCS#1.5 padding, and SHA-256.\n\nSee \"`RSA_PKCS1_*` Details\" in
             `ring::signature`'s module-level documentation for more details."
);
rsa_params!(
    RSA_PKCS1_2048_8192_SHA384,
    2048,
    &super::RSA_PKCS1_SHA384,
    "Verification of signatures using RSA keys of 2048-8192 bits,
             PKCS#1.5 padding, and SHA-384.\n\nSee \"`RSA_PKCS1_*` Details\" in
             `ring::signature`'s module-level documentation for more details."
);
rsa_params!(
    RSA_PKCS1_2048_8192_SHA512,
    2048,
    &super::RSA_PKCS1_SHA512,
    "Verification of signatures using RSA keys of 2048-8192 bits,
             PKCS#1.5 padding, and SHA-512.\n\nSee \"`RSA_PKCS1_*` Details\" in
             `ring::signature`'s module-level documentation for more details."
);
rsa_params!(
    RSA_PKCS1_1024_8192_SHA512_FOR_LEGACY_USE_ONLY,
    1024,
    &super::RSA_PKCS1_SHA512,
    "Verification of signatures using RSA keys of 1024-8192 bits,
             PKCS#1.5 padding, and SHA-512.\n\nSee \"`RSA_PKCS1_*` Details\" in
             `ring::signature`'s module-level documentation for more details."
);
rsa_params!(
    RSA_PKCS1_3072_8192_SHA384,
    3072,
    &super::RSA_PKCS1_SHA384,
    "Verification of signatures using RSA keys of 3072-8192 bits,
             PKCS#1.5 padding, and SHA-384.\n\nSee \"`RSA_PKCS1_*` Details\" in
             `ring::signature`'s module-level documentation for more details."
);

rsa_params!(
    RSA_PSS_2048_8192_SHA256,
    2048,
    &super::RSA_PSS_SHA256,
    "Verification of signatures using RSA keys of 2048-8192 bits,
             PSS padding, and SHA-256.\n\nSee \"`RSA_PSS_*` Details\" in
             `ring::signature`'s module-level documentation for more details."
);
rsa_params!(
    RSA_PSS_2048_8192_SHA384,
    2048,
    &super::RSA_PSS_SHA384,
    "Verification of signatures using RSA keys of 2048-8192 bits,
             PSS padding, and SHA-384.\n\nSee \"`RSA_PSS_*` Details\" in
             `ring::signature`'s module-level documentation for more details."
);
rsa_params!(
    RSA_PSS_2048_8192_SHA512,
    2048,
    &super::RSA_PSS_SHA512,
    "Verification of signatures using RSA keys of 2048-8192 bits,
             PSS padding, and SHA-512.\n\nSee \"`RSA_PSS_*` Details\" in
             `ring::signature`'s module-level documentation for more details."
);

/// Low-level API for the verification of RSA signatures.
///
/// When the public key is in DER-encoded PKCS#1 ASN.1 format, it is
/// recommended to use `ring::signature::verify()` with
/// `ring::signature::RSA_PKCS1_*`, because `ring::signature::verify()`
/// will handle the parsing in that case. Otherwise, this function can be used
/// to pass in the raw bytes for the public key components as
/// `untrusted::Input` arguments.
//
// There are a small number of tests that test this directly, but the
// test coverage for this function mostly depends on the test coverage for the
// `signature::VerificationAlgorithm` implementation for `RsaParameters`. If we
// change that, test coverage for `verify_rsa()` will need to be reconsidered.
// (The NIST test vectors were originally in a form that was optimized for
// testing `verify_rsa` directly, but the testing work for RSA PKCS#1
// verification was done during the implementation of
// `signature::VerificationAlgorithm`, before `verify_rsa` was factored out).
#[derive(Debug)]
pub struct RsaPublicKeyComponents<B: AsRef<[u8]> + core::fmt::Debug> {
    /// The public modulus, encoded in big-endian bytes without leading zeros.
    pub n: B,

    /// The public exponent, encoded in big-endian bytes without leading zeros.
    pub e: B,
}

impl<B: Copy> Copy for RsaPublicKeyComponents<B> where B: AsRef<[u8]> + core::fmt::Debug {}

impl<B: Clone> Clone for RsaPublicKeyComponents<B>
where
    B: AsRef<[u8]> + core::fmt::Debug,
{
    fn clone(&self) -> Self {
        Self {
            n: self.n.clone(),
            e: self.e.clone(),
        }
    }
}

impl<B> RsaPublicKeyComponents<B>
where
    B: AsRef<[u8]> + core::fmt::Debug,
{
    /// Verifies that `signature` is a valid signature of `message` using `self`
    /// as the public key. `params` determine what algorithm parameters
    /// (padding, digest algorithm, key length range, etc.) are used in the
    /// verification.
    pub fn verify(
        &self,
        params: &RsaParameters,
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), error::Unspecified> {
        use openssl::bn::BigNum;

        let n = BigNum::from_slice(self.n.as_ref())
            .map_err(|_| error::Unspecified)?;
        let e = BigNum::from_slice(self.e.as_ref())
            .map_err(|_| error::Unspecified)?;
        let public_key = openssl::rsa::Rsa::from_public_components(n, e)
            .map_err(|_| error::Unspecified)?;

        verify(params, public_key, message, signature)
    }
}

fn verify(
    params: &RsaParameters,
    public_key: openssl::rsa::Rsa<pkey::Public>,
    msg: &[u8],
    signature: &[u8],
) -> Result<(), error::Unspecified> {
    const MIN_PUB_EXPONENT: u32 = 3;
    const MAX_PUB_EXPONENT: u64 = (1u64 << 33) - 1;

    let public_key = {
        let n = public_key.n();
        let e = public_key.e();

        let bint3 = openssl::bn::BigNum::from_u32(MIN_PUB_EXPONENT).unwrap();
        let bint33 = openssl::bn::BigNum::from_slice(&MAX_PUB_EXPONENT.to_be_bytes()).unwrap();

        if e < &bint3 {
            return Err(error::KeyRejected::too_small().into());
        }

        if e > &bint33 {
            return Err(error::KeyRejected::too_large().into());
        }

        if n.num_bits() < params.min_bits as i32 {
            return Err(error::KeyRejected::too_small().into());
        }

        if public_key.size() as usize != signature.len() {
            return Err(error::Unspecified);
        }

        pkey::PKey::from_rsa(public_key)
            .map_err(|_| error::Unspecified)?
    };

    let scheme = params.padding_alg.scheme();
    let mut verifier = openssl::sign::Verifier::new(scheme.hash, &public_key)
        .map_err(|_| error::Unspecified)?;
    verifier.set_rsa_padding(scheme.padding)
        .map_err(|_| error::Unspecified)?;

    if verifier.verify_oneshot(signature, msg)
        .map_err(|_| error::Unspecified)?
    {
        Ok(())
    } else {
        Err(error::Unspecified)
    }
}
