use super::{Curve, ELEM_MAX_BYTES, SEED_MAX_BYTES};
use crate::{error, rand};

pub struct KeyPair {
    pub(crate) seed: Seed,
    public_key: PublicKey,
}

impl KeyPair {
    pub fn derive(seed: Seed) -> Result<Self, error::Unspecified> {
        let public_key = seed.compute_public_key()?;
        Ok(Self { seed, public_key })
    }

    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }
    pub fn split(self) -> (Seed, PublicKey) {
        (self.seed, self.public_key)
    }
}

pub struct Seed {
    bytes: [u8; SEED_MAX_BYTES],
    curve: &'static Curve,
}

impl Seed {
    pub(crate) fn generate(
        curve: &'static Curve,
        rng: &dyn rand::SecureRandom,
    ) -> Result<Self, error::Unspecified> {
        let mut r = Self {
            bytes: [0u8; SEED_MAX_BYTES],
            curve,
        };
        (curve.generate_private_key)(rng, &mut r.bytes[..curve.elem_scalar_seed_len])?;
        Ok(r)
    }

    pub(crate) fn from_bytes(
        curve: &'static Curve,
        bytes: untrusted::Input,
    ) -> Result<Seed, error::Unspecified> {
        let bytes = bytes.as_slice_less_safe();
        if curve.elem_scalar_seed_len != bytes.len() {
            return Err(error::Unspecified);
        }
        (curve.check_private_key_bytes)(bytes)?;
        let mut r = Self {
            bytes: [0; SEED_MAX_BYTES],
            curve,
        };
        r.bytes[..curve.elem_scalar_seed_len].copy_from_slice(bytes);
        Ok(r)
    }

    pub fn bytes_less_safe(&self) -> &[u8] {
        &self.bytes[..self.curve.elem_scalar_seed_len]
    }

    pub fn compute_public_key(&self) -> Result<PublicKey, error::Unspecified> {
        let mut public_key = PublicKey {
            bytes: [0u8; PUBLIC_KEY_MAX_LEN],
            len: self.curve.public_key_len,
        };
        (self.curve.public_from_private)(&mut public_key.bytes[..public_key.len], self)?;
        Ok(public_key)
    }
}

#[derive(Copy, Clone)]
pub struct PublicKey {
    bytes: [u8; PUBLIC_KEY_MAX_LEN],
    len: usize,
}

impl AsRef<[u8]> for PublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

/// The maximum length, in bytes, of an encoded public key.
pub const PUBLIC_KEY_MAX_LEN: usize = 1 + (2 * ELEM_MAX_BYTES);
