// Copyright 2015-2019 Brian Smith.
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

//! SHA-2 and the legacy SHA-1 digest algorithm.
//!
//! If all the data is available in a single contiguous slice then the `digest`
//! function should be used. Otherwise, the digest can be calculated in
//! multiple steps using `Context`.

// Note on why are we doing things the hard way: It would be easy to implement
// this using the C `EVP_MD`/`EVP_MD_CTX` interface. However, if we were to do
// things that way, we'd have a hard dependency on `malloc` and other overhead.
// The goal for this implementation is to drive the overhead as close to zero
// as possible.

use crate::{ debug, polyfill };
use core::num::Wrapping;
use sha1::Sha1;
use sha2::{ Digest as _, Sha256, Sha384, Sha512, Sha512_256 };
use sha2::digest::core_api::{ BlockSizeUser, OutputSizeUser };
use sha2::digest::generic_array::GenericArray;
use sha2::digest::typenum::Unsigned;


/// A context for multi-step (Init-Update-Finish) digest calculations.
///
/// # Examples
///
/// ```
/// use ziwaan::digest;
///
/// let one_shot = digest::digest(&digest::SHA384, b"hello, world");
///
/// let mut ctx = digest::Context::new(&digest::SHA384);
/// ctx.update(b"hello");
/// ctx.update(b", ");
/// ctx.update(b"world");
/// let multi_part = ctx.finish();
///
/// assert_eq!(&one_shot.as_ref(), &multi_part.as_ref());
/// ```
#[derive(Clone)]
pub struct Context {
    algorithm: &'static Algorithm,
    hash: HashInner,
}

impl Context {
    /// Constructs a new context.
    pub fn new(algorithm: &'static Algorithm) -> Self {
        let hash = (algorithm.init)();
        Self { algorithm, hash }
    }

    /// Updates the digest with all the data in `data`. `update` may be called
    /// zero or more times until `finish` is called. It must not be called
    /// after `finish` has been called.
    pub fn update(&mut self, data: &[u8]) {
        (self.algorithm.update)(&mut self.hash, data);
    }

    /// Finalizes the digest calculation and returns the digest value. `finish`
    /// consumes the context so it cannot be (mis-)used after `finish` has been
    /// called.
    pub fn finish(self) -> Digest {
        let output = (self.algorithm.finish)(self.hash);
        Digest {
            value: output,
            algorithm: self.algorithm
        }
    }

    /// The algorithm that this context is using.
    #[inline(always)]
    pub fn algorithm(&self) -> &'static Algorithm {
        self.algorithm
    }
}

/// Returns the digest of `data` using the given digest algorithm.
///
/// # Examples:
///
/// ```
/// # #[cfg(feature = "alloc")]
/// # {
/// use ziwaan::{digest, test};
/// let expected_hex = "09ca7e4eaa6e8ae9c7d261167129184883644d07dfba7cbfbc4c8a2e08360d5b";
/// let expected: Vec<u8> = test::from_hex(expected_hex).unwrap();
/// let actual = digest::digest(&digest::SHA256, b"hello, world");
///
/// assert_eq!(&expected, &actual.as_ref());
/// # }
/// ```
pub fn digest(algorithm: &'static Algorithm, data: &[u8]) -> Digest {
    let mut ctx = Context::new(algorithm);
    ctx.update(data);
    ctx.finish()
}

/// A calculated digest value.
///
/// Use `as_ref` to get the value as a `&[u8]`.
#[derive(Clone, Copy)]
pub struct Digest {
    value: Output,
    algorithm: &'static Algorithm,
}

#[derive(Clone, Copy)]
enum Output {
    Sha1(GenericArray<u8, <Sha1 as OutputSizeUser>::OutputSize>),
    Sha256(GenericArray<u8, <Sha256 as OutputSizeUser>::OutputSize>),
    Sha384(GenericArray<u8, <Sha384 as OutputSizeUser>::OutputSize>),
    Sha512(GenericArray<u8, <Sha512 as OutputSizeUser>::OutputSize>),
    Sha512_256(GenericArray<u8, <Sha512_256 as OutputSizeUser>::OutputSize>)
}

impl Digest {
    /// The algorithm that was used to calculate the digest value.
    #[inline(always)]
    pub fn algorithm(&self) -> &'static Algorithm {
        self.algorithm
    }
}

impl AsRef<[u8]> for Digest {
    #[inline(always)]
    fn as_ref(&self) -> &[u8] {
        match &self.value {
            Output::Sha1(v) => v.as_slice(),
            Output::Sha256(v) => v.as_slice(),
            Output::Sha384(v) => v.as_slice(),
            Output::Sha512(v) => v.as_slice(),
            Output::Sha512_256(v) => v.as_slice(),
        }
    }
}

impl core::fmt::Debug for Digest {
    fn fmt(&self, fmt: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(fmt, "{:?}:", self.algorithm)?;
        debug::write_hex_bytes(fmt, self.as_ref())
    }
}

#[derive(Clone)]
enum HashInner {
    Sha1(Sha1),
    Sha256(Sha256),
    Sha384(Sha384),
    Sha512(Sha512),
    Sha512_256(Sha512_256)
}

/// A digest algorithm.
pub struct Algorithm {
    /// The length of a finalized digest.
    pub output_len: usize,

    /// The size of the chaining value of the digest function, in bytes. For
    /// non-truncated algorithms (SHA-1, SHA-256, SHA-512), this is equal to
    /// `output_len`. For truncated algorithms (e.g. SHA-384, SHA-512/256),
    /// this is equal to the length before truncation. This is mostly helpful
    /// for determining the size of an HMAC key that is appropriate for the
    /// digest algorithm.
    pub chaining_len: usize,

    /// The internal block length.
    pub block_len: usize,

    init: fn() -> HashInner,
    update: fn(hash: &mut HashInner, data: &[u8]),
    finish: fn(hash: HashInner) -> Output,

    id: AlgorithmID,
}

#[derive(Debug, Eq, PartialEq)]
enum AlgorithmID {
    SHA1,
    SHA256,
    SHA384,
    SHA512,
    SHA512_256,
}

impl PartialEq for Algorithm {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

impl Eq for Algorithm {}

derive_debug_via_id!(Algorithm);

/// SHA-1 as specified in [FIPS 180-4]. Deprecated.
///
/// [FIPS 180-4]: http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf
pub static SHA1_FOR_LEGACY_USE_ONLY: Algorithm = Algorithm {
    output_len: <<Sha1 as OutputSizeUser>::OutputSize>::USIZE,
    chaining_len: <<Sha1 as BlockSizeUser>::BlockSize>::USIZE,
    block_len: <<Sha1 as BlockSizeUser>::BlockSize>::USIZE,
    init: sha1_init,
    update: sha1_update,
    finish: sha1_finish,
    id: AlgorithmID::SHA1,
};

fn sha1_init() -> HashInner {
    HashInner::Sha1(Sha1::new())
}

fn sha1_update(hasher: &mut HashInner, data: &[u8]) {
    let hasher = match hasher {
        HashInner::Sha1(hasher) => hasher,
        _ => unreachable!()
    };

    hasher.update(data);
}

fn sha1_finish(hasher: HashInner) -> Output {
    let hasher = match hasher {
        HashInner::Sha1(hasher) => hasher,
        _ => unreachable!()
    };

    Output::Sha1(hasher.finalize())
}

/// SHA-256 as specified in [FIPS 180-4].
///
/// [FIPS 180-4]: http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf
pub static SHA256: Algorithm = Algorithm {
    output_len: <<Sha256 as OutputSizeUser>::OutputSize>::USIZE,
    chaining_len: <<Sha256 as BlockSizeUser>::BlockSize>::USIZE,
    block_len: <<Sha256 as BlockSizeUser>::BlockSize>::USIZE,
    init: sha256_init,
    update: sha256_update,
    finish: sha256_finish,
    id: AlgorithmID::SHA256,
};

fn sha256_init() -> HashInner {
    HashInner::Sha256(Sha256::new())
}

fn sha256_update(hasher: &mut HashInner, data: &[u8]) {
    let hasher = match hasher {
        HashInner::Sha256(hasher) => hasher,
        _ => unreachable!()
    };

    hasher.update(data);
}

fn sha256_finish(hasher: HashInner) -> Output {
    let hasher = match hasher {
        HashInner::Sha256(hasher) => hasher,
        _ => unreachable!()
    };

    Output::Sha256(hasher.finalize())
}

/// SHA-384 as specified in [FIPS 180-4].
///
/// [FIPS 180-4]: http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf
pub static SHA384: Algorithm = Algorithm {
    output_len: <<Sha384 as OutputSizeUser>::OutputSize>::USIZE,
    chaining_len: <<Sha384 as BlockSizeUser>::BlockSize>::USIZE,
    block_len: <<Sha384 as BlockSizeUser>::BlockSize>::USIZE,
    init: sha384_init,
    update: sha384_update,
    finish: sha384_finish,
    id: AlgorithmID::SHA384,
};

fn sha384_init() -> HashInner {
    HashInner::Sha384(Sha384::new())
}

fn sha384_update(hasher: &mut HashInner, data: &[u8]) {
    let hasher = match hasher {
        HashInner::Sha384(hasher) => hasher,
        _ => unreachable!()
    };

    hasher.update(data);
}

fn sha384_finish(hasher: HashInner) -> Output {
    let hasher = match hasher {
        HashInner::Sha384(hasher) => hasher,
        _ => unreachable!()
    };

    Output::Sha384(hasher.finalize())
}

/// SHA-512 as specified in [FIPS 180-4].
///
/// [FIPS 180-4]: http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf
pub static SHA512: Algorithm = Algorithm {
    output_len: <<Sha512 as OutputSizeUser>::OutputSize>::USIZE,
    chaining_len: <<Sha512 as BlockSizeUser>::BlockSize>::USIZE,
    block_len: <<Sha512 as BlockSizeUser>::BlockSize>::USIZE,
    init: sha512_init,
    update: sha512_update,
    finish: sha512_finish,
    id: AlgorithmID::SHA512,
};

fn sha512_init() -> HashInner {
    HashInner::Sha512(Sha512::new())
}

fn sha512_update(hasher: &mut HashInner, data: &[u8]) {
    let hasher = match hasher {
        HashInner::Sha512(hasher) => hasher,
        _ => unreachable!()
    };

    hasher.update(data);
}

fn sha512_finish(hasher: HashInner) -> Output {
    let hasher = match hasher {
        HashInner::Sha512(hasher) => hasher,
        _ => unreachable!()
    };

    Output::Sha512(hasher.finalize())
}


/// SHA-512/256 as specified in [FIPS 180-4].
///
/// This is *not* the same as just truncating the output of SHA-512, as
/// SHA-512/256 has its own initial state distinct from SHA-512's initial
/// state.
///
/// [FIPS 180-4]: http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf
pub static SHA512_256: Algorithm = Algorithm {
    output_len: <<Sha512_256 as OutputSizeUser>::OutputSize>::USIZE,
    chaining_len: <<Sha512_256 as BlockSizeUser>::BlockSize>::USIZE,
    block_len: <<Sha512_256 as BlockSizeUser>::BlockSize>::USIZE,
    init: sha512_256_init,
    update: sha512_256_update,
    finish: sha512_256_finish,
    id: AlgorithmID::SHA512_256,
};

fn sha512_256_init() -> HashInner {
    HashInner::Sha512_256(Sha512_256::new())
}

fn sha512_256_update(hasher: &mut HashInner, data: &[u8]) {
    let hasher = match hasher {
        HashInner::Sha512_256(hasher) => hasher,
        _ => unreachable!()
    };

    hasher.update(data);
}

fn sha512_256_finish(hasher: HashInner) -> Output {
    let hasher = match hasher {
        HashInner::Sha512_256(hasher) => hasher,
        _ => unreachable!()
    };

    Output::Sha512_256(hasher.finalize())
}

/// The maximum block length (`Algorithm::block_len`) of all the algorithms in
/// this module.
pub const MAX_BLOCK_LEN: usize = 1024 / 8;

/// The maximum output length (`Algorithm::output_len`) of all the algorithms
/// in this module.
pub const MAX_OUTPUT_LEN: usize = 512 / 8;

/// The maximum chaining length (`Algorithm::chaining_len`) of all the
/// algorithms in this module.
pub const MAX_CHAINING_LEN: usize = MAX_OUTPUT_LEN;

/// The length of the output of SHA-1, in bytes.
pub const SHA1_OUTPUT_LEN: usize = <<Sha1 as OutputSizeUser>::OutputSize>::USIZE;

/// The length of the output of SHA-256, in bytes.
pub const SHA256_OUTPUT_LEN: usize = <<Sha256 as OutputSizeUser>::OutputSize>::USIZE;

/// The length of the output of SHA-384, in bytes.
pub const SHA384_OUTPUT_LEN: usize = <<Sha384 as OutputSizeUser>::OutputSize>::USIZE;

/// The length of the output of SHA-512, in bytes.
pub const SHA512_OUTPUT_LEN: usize = <<Sha512 as OutputSizeUser>::OutputSize>::USIZE;

/// The length of the output of SHA-512/256, in bytes.
pub const SHA512_256_OUTPUT_LEN: usize = <<Sha512_256 as OutputSizeUser>::OutputSize>::USIZE;
