// Copyright 2016 Brian Smith.
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

//! Elliptic curve operations on P-256 & P-384.

use crate::{ec, error, io::der, pkcs8};

pub(crate) fn key_pair_from_pkcs8(
    curve: &'static ec::Curve,
    template: &pkcs8::Template,
    input: untrusted::Input,
) -> Result<ec::KeyPair, error::KeyRejected> {
    let (ec_private_key, _) = pkcs8::unwrap_key(template, pkcs8::Version::V1Only, input)?;
    let (private_key, public_key) =
        ec_private_key.read_all(error::KeyRejected::invalid_encoding(), |input| {
            // https://tools.ietf.org/html/rfc5915#section-3
            der::nested(
                input,
                der::Tag::Sequence,
                error::KeyRejected::invalid_encoding(),
                |input| key_pair_from_pkcs8_(template, input),
            )
        })?;
    key_pair_from_bytes(curve, private_key, public_key)
}

fn key_pair_from_pkcs8_<'a>(
    template: &pkcs8::Template,
    input: &mut untrusted::Reader<'a>,
) -> Result<(untrusted::Input<'a>, untrusted::Input<'a>), error::KeyRejected> {
    let version = der::small_nonnegative_integer(input)
        .map_err(|error::Unspecified| error::KeyRejected::invalid_encoding())?;
    if version != 1 {
        return Err(error::KeyRejected::version_not_supported());
    }

    let private_key = der::expect_tag_and_get_value(input, der::Tag::OctetString)
        .map_err(|error::Unspecified| error::KeyRejected::invalid_encoding())?;

    // [0] parameters (optional).
    if input.peek(u8::from(der::Tag::ContextSpecificConstructed0)) {
        let actual_alg_id =
            der::expect_tag_and_get_value(input, der::Tag::ContextSpecificConstructed0)
                .map_err(|error::Unspecified| error::KeyRejected::invalid_encoding())?;
        if actual_alg_id != template.curve_oid() {
            return Err(error::KeyRejected::wrong_algorithm());
        }
    }

    // [1] publicKey. The RFC says it is optional, but we require it
    // to be present.
    let public_key = der::nested(
        input,
        der::Tag::ContextSpecificConstructed1,
        error::Unspecified,
        der::bit_string_with_no_unused_bits,
    )
    .map_err(|error::Unspecified| error::KeyRejected::invalid_encoding())?;

    Ok((private_key, public_key))
}

pub(crate) fn key_pair_from_bytes(
    curve: &'static ec::Curve,
    private_key_bytes: untrusted::Input,
    public_key_bytes: untrusted::Input,
) -> Result<ec::KeyPair, error::KeyRejected> {
    let seed = ec::Seed::from_bytes(curve, private_key_bytes)
        .map_err(|error::Unspecified| error::KeyRejected::invalid_component())?;

    let r = ec::KeyPair::derive(seed)
        .map_err(|error::Unspecified| error::KeyRejected::unexpected_error())?;
    if public_key_bytes != *r.public_key().as_ref() {
        return Err(error::KeyRejected::inconsistent_components());
    }

    Ok(r)
}

mod curve;
pub mod ecdh;
// pub mod ecdsa;
