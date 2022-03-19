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

#![doc = include_str!("../README.md")]

#![allow(
    clippy::collapsible_if,
    clippy::identity_op,
    clippy::len_without_is_empty,
    clippy::len_zero,
    clippy::let_unit_value,
    clippy::many_single_char_names,
    clippy::needless_range_loop,
    clippy::new_without_default,
    clippy::neg_cmp_op_on_partial_ord,
    clippy::range_plus_one,
    clippy::too_many_arguments,
    clippy::trivially_copy_pass_by_ref,
    clippy::type_complexity,
    clippy::unreadable_literal,
    missing_copy_implementations,
    missing_debug_implementations,
    non_camel_case_types,
    non_snake_case,
    unsafe_code
)]
// `#[derive(...)]` uses `trivial_numeric_casts` and `unused_qualifications`
// internally.
#![deny(missing_docs, unused_qualifications, variant_size_differences)]
#![forbid(unused_results)]
#![no_std]

#[cfg(feature = "alloc")]
extern crate alloc;

#[macro_use]
mod debug;

#[macro_use]
pub mod test;

mod bits;
mod polyfill;
mod ec;

pub mod error;
pub mod constant_time;
pub mod rand;
pub mod aead;
pub mod digest;
pub mod hmac;
pub mod hkdf;
pub mod io;
pub mod pbkdf2;
pub mod pkcs8;
pub mod agreement;
pub mod signature;

mod sealed {
    /// Traits that are designed to only be implemented internally in *ring*.
    //
    // Usage:
    // ```
    // use crate::sealed;
    //
    // pub trait MyType: sealed::Sealed {
    //     // [...]
    // }
    //
    // impl sealed::Sealed for MyType {}
    // ```
    pub trait Sealed {}
}
