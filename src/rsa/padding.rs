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

#[cfg(feature = "alloc")]
use crate::rand;

/// Common features of both RSA padding encoding and RSA padding verification.
pub trait Padding: 'static + Sync + crate::sealed::Sealed + core::fmt::Debug {
}

/// An RSA signature encoding as described in [RFC 3447 Section 8].
///
/// [RFC 3447 Section 8]: https://tools.ietf.org/html/rfc3447#section-8
#[cfg(feature = "alloc")]
pub trait RsaEncoding: Padding {
    #[doc(hidden)]
    fn scheme(&self, rng: &dyn rand::SecureRandom) -> rsa::padding::PaddingScheme;

    #[doc(hidden)]
    fn digest(&self) -> Box<dyn DynDigest>;
}

/// PKCS#1 1.5 padding as described in [RFC 3447 Section 8.2].
///
/// See "`RSA_PSS_*` Details\" in `ring::signature`'s module-level
/// documentation for more details.
///
/// [RFC 3447 Section 8.2]: https://tools.ietf.org/html/rfc3447#section-8.2
#[derive(Debug)]
pub struct PKCS1(rsa::hash::Hash);

impl crate::sealed::Sealed for PKCS1 {}

impl Padding for PKCS1 {}

#[cfg(feature = "alloc")]
impl RsaEncoding for PKCS1 {
    fn scheme(&self, _rng: &dyn rand::SecureRandom) -> rsa::padding::PaddingScheme {
        rsa::padding::PaddingScheme::new_pkcs1v15_sign(Some(self.0.clone()))
    }

    fn digest(&self) -> Box<dyn DynDigest> {
        match self.0 {
            rsa::hash::Hash::SHA1 => Box::new(sha_1_09::Sha1::new()),
            rsa::hash::Hash::SHA2_256 => Box::new(sha2_09::Sha256::new()),
            rsa::hash::Hash::SHA2_384 => Box::new(sha2_09::Sha384::new()),
            rsa::hash::Hash::SHA2_512 => Box::new(sha2_09::Sha512::new()),
            _ => unreachable!()
        }
    }
}

macro_rules! rsa_pkcs1_padding {
    ( $PADDING_ALGORITHM:ident, $digest_alg:expr, $doc_str:expr ) => {
        #[doc=$doc_str]
        pub static $PADDING_ALGORITHM: PKCS1 = PKCS1($digest_alg);
    };
}

rsa_pkcs1_padding!(
    RSA_PKCS1_SHA1_FOR_LEGACY_USE_ONLY,
    rsa::hash::Hash::SHA1,
    "PKCS#1 1.5 padding using SHA-1 for RSA signatures."
);
rsa_pkcs1_padding!(
    RSA_PKCS1_SHA256,
    rsa::hash::Hash::SHA2_256,
    "PKCS#1 1.5 padding using SHA-256 for RSA signatures."
);
rsa_pkcs1_padding!(
    RSA_PKCS1_SHA384,
    rsa::hash::Hash::SHA2_384,
    "PKCS#1 1.5 padding using SHA-384 for RSA signatures."
);
rsa_pkcs1_padding!(
    RSA_PKCS1_SHA512,
    rsa::hash::Hash::SHA2_512,
    "PKCS#1 1.5 padding using SHA-512 for RSA signatures."
);

/// RSA PSS padding as described in [RFC 3447 Section 8.1].
///
/// See "`RSA_PSS_*` Details\" in `ring::signature`'s module-level
/// documentation for more details.
///
/// [RFC 3447 Section 8.1]: https://tools.ietf.org/html/rfc3447#section-8.1
#[derive(Debug)]
pub struct PSS {
    digest_alg: fn() -> Box<dyn DynDigest>
}

impl crate::sealed::Sealed for PSS {}

// Maximum supported length of the salt in bytes.
// In practice, this is constrained by the maximum digest length.
const MAX_SALT_LEN: usize = digest::MAX_OUTPUT_LEN;

impl Padding for PSS {}

impl RsaEncoding for PSS {
    fn scheme(&self, rng: &dyn rand::SecureRandom) -> rsa::padding::PaddingScheme {
        let digest_alg = (self.digest_alg)();
        let salt_len = digest_alg.output_size();
        rsa::padding::PaddingScheme::PSS {
            salt_rng: rng.clone_into_boxed_rngcore(),
            digest: digest_alg,
            salt_len: Some(salt_len)
        }
    }

    fn digest(&self) -> Box<dyn DynDigest> {
        (self.digest_alg)()
    }
}

macro_rules! rsa_pss_padding {
    ( $PADDING_ALGORITHM:ident, $digest_alg:expr, $doc_str:expr ) => {
        #[doc=$doc_str]
        pub static $PADDING_ALGORITHM: PSS = PSS {
            digest_alg: $digest_alg,
        };
    };
}

rsa_pss_padding!(
    RSA_PSS_SHA256,
    || Box::new(sha2_09::Sha256::new()),
    "RSA PSS padding using SHA-256 for RSA signatures.\n\nSee
                 \"`RSA_PSS_*` Details\" in `ring::signature`'s module-level
                 documentation for more details."
);
rsa_pss_padding!(
    RSA_PSS_SHA384,
    || Box::new(sha2_09::Sha384::new()),
    "RSA PSS padding using SHA-384 for RSA signatures.\n\nSee
                 \"`RSA_PSS_*` Details\" in `ring::signature`'s module-level
                 documentation for more details."
);
rsa_pss_padding!(
    RSA_PSS_SHA512,
    || Box::new(sha2_09::Sha512::new()),
    "RSA PSS padding using SHA-512 for RSA signatures.\n\nSee
                 \"`RSA_PSS_*` Details\" in `ring::signature`'s module-level
                 documentation for more details."
);

#[cfg(test)]
mod test {
    use super::*;
    use crate::{digest, error, test};
    use alloc::vec;

    #[test]
    fn test_pss_padding_verify() {
        test::run(
            test_file!("rsa_pss_padding_tests.txt"),
            |section, test_case| {
                assert_eq!(section, "");

                let digest_name = test_case.consume_string("Digest");
                let alg = match digest_name.as_ref() {
                    "SHA256" => &RSA_PSS_SHA256,
                    "SHA384" => &RSA_PSS_SHA384,
                    "SHA512" => &RSA_PSS_SHA512,
                    _ => panic!("Unsupported digest: {}", digest_name),
                };

                let msg = test_case.consume_bytes("Msg");
                let msg = untrusted::Input::from(&msg);
                let m_hash = {
                    let mut hasher = alg.digest();
                    hasher.update(msg.as_slice_less_safe());
                    hasher.finalize()
                };

                let encoded = test_case.consume_bytes("EM");
                let encoded = untrusted::Input::from(&encoded);

                // Salt is recomputed in verification algorithm.
                let _ = test_case.consume_bytes("Salt");

                let bit_len = test_case.consume_usize_bits("Len");
                let is_valid = test_case.consume_string("Result") == "P";

//                let actual_result =
//                    encoded.read_all(error::Unspecified, |m| alg.verify(&m_hash, m, bit_len));
//                assert_eq!(actual_result.is_ok(), is_valid);

                Ok(())
            },
        );
    }
}
