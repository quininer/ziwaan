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

use crate::{error, sealed, signature};
use core::convert::TryInto;

/// Parameters for EdDSA signing and verification.
pub struct EdDSAParameters;

impl core::fmt::Debug for EdDSAParameters {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> Result<(), core::fmt::Error> {
        write!(f, "ring::signature::ED25519")
    }
}

/// Verification of [Ed25519] signatures.
///
/// Ed25519 uses SHA-512 as the digest algorithm.
///
/// [Ed25519]: https://ed25519.cr.yp.to/
pub static ED25519: EdDSAParameters = EdDSAParameters {};

impl signature::VerificationAlgorithm for EdDSAParameters {
    fn verify(
        &self,
        public_key: untrusted::Input,
        msg: untrusted::Input,
        signature: untrusted::Input,
    ) -> Result<(), error::Unspecified> {
        use ed25519_dalek::Verifier;

        let public_key = public_key.as_slice_less_safe();
        let public_key = ed25519_dalek::PublicKey::from_bytes(public_key)
            .map_err(|_| error::Unspecified)?;
        let sig = ed25519_dalek::Signature::from_bytes(signature.as_slice_less_safe())
            .map_err(|_| error::Unspecified)?;

        public_key.verify(msg.as_slice_less_safe(), &sig)
            .map_err(|_| error::Unspecified)
    }
}

impl sealed::Sealed for EdDSAParameters {}
