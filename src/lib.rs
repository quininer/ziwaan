#![no_std]

#[cfg(feature = "alloc")]
extern crate alloc;

#[macro_use]
mod debug;

pub mod error;
pub mod constant_time;
pub mod polyfill;
pub mod aead;
