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

use alloc::boxed::Box;
use digest_09::DynDigest;
use sha2_09::Digest as _;
// use super::PUBLIC_KEY_PUBLIC_MODULUS_MAX_LEN;
use crate::{bits, digest, error, io::der};

/// Common features of both RSA padding encoding and RSA padding verification.
pub trait Padding: 'static + Sync + crate::sealed::Sealed + core::fmt::Debug {
}

/// An RSA signature encoding as described in [RFC 3447 Section 8].
///
/// [RFC 3447 Section 8]: https://tools.ietf.org/html/rfc3447#section-8
#[cfg(feature = "alloc")]
pub trait RsaEncoding: Padding {
    #[doc(hidden)]
    fn scheme(&self) -> PaddingScheme;
}

pub struct PaddingScheme {
    pub(crate) hash: openssl::hash::MessageDigest,
    pub(crate) padding: openssl::rsa::Padding
}

/// PKCS#1 1.5 padding as described in [RFC 3447 Section 8.2].
///
/// See "`RSA_PSS_*` Details\" in `ring::signature`'s module-level
/// documentation for more details.
///
/// [RFC 3447 Section 8.2]: https://tools.ietf.org/html/rfc3447#section-8.2
#[derive(Debug)]
pub struct PKCS1(fn() -> openssl::hash::MessageDigest);

impl crate::sealed::Sealed for PKCS1 {}

impl Padding for PKCS1 {}

#[cfg(feature = "alloc")]
impl RsaEncoding for PKCS1 {
    fn scheme(&self) -> PaddingScheme {
        PaddingScheme {
            hash: (self.0)(),
            padding: openssl::rsa::Padding::PKCS1
        }
    }
}

macro_rules! rsa_pkcs1_padding {
    ( $PADDING_ALGORITHM:ident, $digest_alg:expr, $doc_str:expr ) => {
        #[doc=$doc_str]
        pub static $PADDING_ALGORITHM: PKCS1 = PKCS1(|| $digest_alg);
    };
}

rsa_pkcs1_padding!(
    RSA_PKCS1_SHA1_FOR_LEGACY_USE_ONLY,
    openssl::hash::MessageDigest::sha1(),
    "PKCS#1 1.5 padding using SHA-1 for RSA signatures."
);
rsa_pkcs1_padding!(
    RSA_PKCS1_SHA256,
    openssl::hash::MessageDigest::sha256(),
    "PKCS#1 1.5 padding using SHA-256 for RSA signatures."
);
rsa_pkcs1_padding!(
    RSA_PKCS1_SHA384,
    openssl::hash::MessageDigest::sha384(),
    "PKCS#1 1.5 padding using SHA-384 for RSA signatures."
);
rsa_pkcs1_padding!(
    RSA_PKCS1_SHA512,
    openssl::hash::MessageDigest::sha512(),
    "PKCS#1 1.5 padding using SHA-512 for RSA signatures."
);

/// RSA PSS padding as described in [RFC 3447 Section 8.1].
///
/// See "`RSA_PSS_*` Details\" in `ring::signature`'s module-level
/// documentation for more details.
///
/// [RFC 3447 Section 8.1]: https://tools.ietf.org/html/rfc3447#section-8.1
#[derive(Debug)]
pub struct PSS(fn() -> openssl::hash::MessageDigest);

impl crate::sealed::Sealed for PSS {}

// Maximum supported length of the salt in bytes.
// In practice, this is constrained by the maximum digest length.
const MAX_SALT_LEN: usize = digest::MAX_OUTPUT_LEN;

impl Padding for PSS {}

impl RsaEncoding for PSS {
    fn scheme(&self) -> PaddingScheme {
        PaddingScheme {
            hash: (self.0)(),
            padding: openssl::rsa::Padding::PKCS1_PSS
        }
    }
}

macro_rules! rsa_pss_padding {
    ( $PADDING_ALGORITHM:ident, $digest_alg:expr, $doc_str:expr ) => {
        #[doc=$doc_str]
        pub static $PADDING_ALGORITHM: PSS = PSS(|| $digest_alg);
    };
}

rsa_pss_padding!(
    RSA_PSS_SHA256,
    openssl::hash::MessageDigest::sha256(),
    "RSA PSS padding using SHA-256 for RSA signatures.\n\nSee
                 \"`RSA_PSS_*` Details\" in `ring::signature`'s module-level
                 documentation for more details."
);
rsa_pss_padding!(
    RSA_PSS_SHA384,
    openssl::hash::MessageDigest::sha384(),
    "RSA PSS padding using SHA-384 for RSA signatures.\n\nSee
                 \"`RSA_PSS_*` Details\" in `ring::signature`'s module-level
                 documentation for more details."
);
rsa_pss_padding!(
    RSA_PSS_SHA512,
    openssl::hash::MessageDigest::sha512(),
    "RSA PSS padding using SHA-512 for RSA signatures.\n\nSee
                 \"`RSA_PSS_*` Details\" in `ring::signature`'s module-level
                 documentation for more details."
);
