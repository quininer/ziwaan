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

//! EdDSA Signatures.

use crate::{
    digest, error,
    io::der,
    pkcs8, rand,
    signature::{self, KeyPair as SigningKeyPair},
};
use core::convert::TryInto;
use sha2::{ Digest, Sha512 };

/// An Ed25519 key pair, for signing.
pub struct Ed25519KeyPair {
    secret_key: ed25519_dalek::ExpandedSecretKey,
    public_key: PublicKey
}

derive_debug_via_field!(Ed25519KeyPair, stringify!(Ed25519KeyPair), public_key);

impl Ed25519KeyPair {
    /// Generates a new key pair and returns the key pair serialized as a
    /// PKCS#8 document.
    ///
    /// The PKCS#8 document will be a v2 `OneAsymmetricKey` with the public key,
    /// as described in [RFC 5958 Section 2]; see [RFC 8410 Section 10.3] for an
    /// example.
    ///
    /// [RFC 5958 Section 2]: https://tools.ietf.org/html/rfc5958#section-2
    /// [RFC 8410 Section 10.3]: https://tools.ietf.org/html/rfc8410#section-10.3
    pub fn generate_pkcs8(
        rng: &dyn rand::SecureRandom,
    ) -> Result<pkcs8::Document, error::Unspecified> {
        let seed: [u8; SEED_LEN] = rand::generate(rng)?.expose();
        let key_pair = Self::from_seed_(&seed);
        Ok(pkcs8::wrap_key(
            &PKCS8_TEMPLATE,
            &seed[..],
            key_pair.public_key().as_ref(),
        ))
    }

    /// Constructs an Ed25519 key pair by parsing an unencrypted PKCS#8 v2
    /// Ed25519 private key.
    ///
    /// `openssl genpkey -algorithm ED25519` generates PKCS# v1 keys, which
    /// require the use of `Ed25519KeyPair::from_pkcs8_maybe_unchecked()`
    /// instead of `Ed25519KeyPair::from_pkcs8()`.
    ///
    /// The input must be in PKCS#8 v2 format, and in particular it must contain
    /// the public key in addition to the private key. `from_pkcs8()` will
    /// verify that the public key and the private key are consistent with each
    /// other.
    ///
    /// If you need to parse PKCS#8 v1 files (without the public key) then use
    /// `Ed25519KeyPair::from_pkcs8_maybe_unchecked()` instead.
    pub fn from_pkcs8(pkcs8: &[u8]) -> Result<Self, error::KeyRejected> {
        let (seed, public_key) =
            unwrap_pkcs8(pkcs8::Version::V2Only, untrusted::Input::from(pkcs8))?;
        Self::from_seed_and_public_key(
            seed.as_slice_less_safe(),
            public_key.unwrap().as_slice_less_safe(),
        )
    }

    /// Constructs an Ed25519 key pair by parsing an unencrypted PKCS#8 v1 or v2
    /// Ed25519 private key.
    ///
    /// `openssl genpkey -algorithm ED25519` generates PKCS# v1 keys.
    ///
    /// It is recommended to use `Ed25519KeyPair::from_pkcs8()`, which accepts
    /// only PKCS#8 v2 files that contain the public key.
    /// `from_pkcs8_maybe_unchecked()` parses PKCS#2 files exactly like
    /// `from_pkcs8()`. It also accepts v1 files. PKCS#8 v1 files do not contain
    /// the public key, so when a v1 file is parsed the public key will be
    /// computed from the private key, and there will be no consistency check
    /// between the public key and the private key.
    ///
    /// PKCS#8 v2 files are parsed exactly like `Ed25519KeyPair::from_pkcs8()`.
    pub fn from_pkcs8_maybe_unchecked(pkcs8: &[u8]) -> Result<Self, error::KeyRejected> {
        let (seed, public_key) =
            unwrap_pkcs8(pkcs8::Version::V1OrV2, untrusted::Input::from(pkcs8))?;
        if let Some(public_key) = public_key {
            Self::from_seed_and_public_key(
                seed.as_slice_less_safe(),
                public_key.as_slice_less_safe(),
            )
        } else {
            Self::from_seed_unchecked(seed.as_slice_less_safe())
        }
    }

    /// Constructs an Ed25519 key pair from the private key seed `seed` and its
    /// public key `public_key`.
    ///
    /// It is recommended to use `Ed25519KeyPair::from_pkcs8()` instead.
    ///
    /// The private and public keys will be verified to be consistent with each
    /// other. This helps avoid misuse of the key (e.g. accidentally swapping
    /// the private key and public key, or using the wrong private key for the
    /// public key). This also detects any corruption of the public or private
    /// key.
    pub fn from_seed_and_public_key(
        seed: &[u8],
        public_key: &[u8],
    ) -> Result<Self, error::KeyRejected> {
        let pair = Self::from_seed_unchecked(seed)?;

        // This implicitly verifies that `public_key` is the right length.
        // XXX: This rejects ~18 keys when they are partially reduced, though
        // those keys are virtually impossible to find.
        if public_key != pair.public_key.as_ref() {
            let err = if public_key.len() != pair.public_key.as_ref().len() {
                error::KeyRejected::invalid_encoding()
            } else {
                error::KeyRejected::inconsistent_components()
            };
            return Err(err);
        }

        Ok(pair)
    }

    /// Constructs a Ed25519 key pair from the private key seed `seed`.
    ///
    /// It is recommended to use `Ed25519KeyPair::from_pkcs8()` instead. When
    /// that is not practical, it is recommended to use
    /// `Ed25519KeyPair::from_seed_and_public_key()` instead.
    ///
    /// Since the public key is not given, the public key will be computed from
    /// the private key. It is not possible to detect misuse or corruption of
    /// the private key since the public key isn't given as input.
    pub fn from_seed_unchecked(seed: &[u8]) -> Result<Self, error::KeyRejected> {
        let seed = seed
            .try_into()
            .map_err(|_| error::KeyRejected::invalid_encoding())?;
        Ok(Self::from_seed_(seed))
    }

    fn from_seed_(seed: &Seed) -> Self {
        let mut h = Sha512::digest(seed);

        h[0]  &= 248;
        h[31] &=  63;
        h[31] |=  64;

        let secret_key = ed25519_dalek::ExpandedSecretKey::from_bytes(&h).unwrap();
        let public_key = PublicKey(ed25519_dalek::PublicKey::from(&secret_key));

        Self { secret_key, public_key }
    }

    /// Returns the signature of the message `msg`.
    pub fn sign(&self, msg: &[u8]) -> signature::Signature {
        signature::Signature::new(|signature_bytes| {
            let sig = self.secret_key.sign(msg, &self.public_key.0);
            let sig = sig.as_ref();

            signature_bytes[..sig.len()].copy_from_slice(sig);

            sig.len()
        })
    }
}

impl signature::KeyPair for Ed25519KeyPair {
    type PublicKey = PublicKey;

    fn public_key(&self) -> &Self::PublicKey {
        &self.public_key
    }
}

#[derive(Clone, Copy)]
pub struct PublicKey(ed25519_dalek::PublicKey);

impl AsRef<[u8]> for PublicKey {
    fn as_ref(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

derive_debug_self_as_ref_hex_bytes!(PublicKey);

fn unwrap_pkcs8(
    version: pkcs8::Version,
    input: untrusted::Input,
) -> Result<(untrusted::Input, Option<untrusted::Input>), error::KeyRejected> {
    let (private_key, public_key) = pkcs8::unwrap_key(&PKCS8_TEMPLATE, version, input)?;
    let private_key = private_key
        .read_all(error::Unspecified, |input| {
            der::expect_tag_and_get_value(input, der::Tag::OctetString)
        })
        .map_err(|error::Unspecified| error::KeyRejected::invalid_encoding())?;
    Ok((private_key, public_key))
}

type Seed = [u8; SEED_LEN];
const SEED_LEN: usize = 32;

static PKCS8_TEMPLATE: pkcs8::Template = pkcs8::Template {
    bytes: include_bytes!("ed25519_pkcs8_v2_template.der"),
    alg_id_range: core::ops::Range { start: 7, end: 12 },
    curve_id_index: 0,
    private_key_index: 0x10,
};
