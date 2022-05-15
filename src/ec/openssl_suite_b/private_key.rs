//! openssl ec private key wrapper
//!
//! The openssl crate doesn't provide a direct ecdh/ecdsa method,
//! so I need to implement it myself.


use core::ptr;
use openssl::bn::BigNumRef;
use openssl::ec::EcGroupRef;
use openssl::hash::MessageDigest;
use openssl::md::MdRef;
use openssl::pkey::{ self, PKey };
use openssl_sys::EVP_PKEY;
use foreign_types::{ ForeignType, ForeignTypeRef };
use crate::error;


pub struct PrivateKey {
    pkey: *mut EVP_PKEY,
}

macro_rules! openssl_cvt {
    ( $ret:expr ) => {
        if $ret != 1 {
            return Err(error::Unspecified);
        }
    };
    ( ptr $ret:expr ) => {{
        let ret = $ret;
        if !ret.is_null() {
            ret
        } else {
            return Err(error::Unspecified)
        }
    }};
}

impl PrivateKey {
    pub fn from_private_key_bignum(group: &EcGroupRef, my_private_key: &BigNumRef)
        -> Result<PrivateKey, error::Unspecified>
    {
        unsafe {
            let ec_key = openssl_cvt!(ptr openssl_sys::EC_KEY_new());
            let ec_key = ScopeGuard(ec_key, |ptr| openssl_sys::EC_KEY_free(ptr));
            openssl_cvt!(openssl_sys::EC_KEY_set_group(ec_key.0, group.as_ptr()));
            openssl_cvt!(openssl_sys::EC_KEY_set_private_key(ec_key.0, my_private_key.as_ptr()));

            let key = openssl_cvt!(ptr openssl_sys::EVP_PKEY_new());
            let key = ScopeGuard(key, |ptr| openssl_sys::EVP_PKEY_free(ptr));
            openssl_cvt!(openssl_sys::EVP_PKEY_assign(key.0, openssl_sys::EVP_PKEY_EC, ec_key.into_inner().cast()));

            Ok(PrivateKey { pkey: key.into_inner() })
        }
    }

    pub fn ecdh(&self, peer_public_key: &PKey<pkey::Public>, out: &mut [u8]) -> Result<(), error::Unspecified> {
        unsafe {
            let ctx = openssl_cvt!(ptr openssl_sys::EVP_PKEY_CTX_new(self.pkey, core::ptr::null_mut()));
            let ctx = ScopeGuard(ctx, |ptr| openssl_sys::EVP_PKEY_CTX_free(ptr));
            openssl_cvt!(openssl_sys::EVP_PKEY_derive_init(ctx.0));
            openssl_cvt!(openssl_sys::EVP_PKEY_derive_set_peer(ctx.0, peer_public_key.as_ptr()));

            let mut len = 0;
            openssl_cvt!(openssl_sys::EVP_PKEY_derive(ctx.0, core::ptr::null_mut(), &mut len));

            if len != out.len() {
                return Err(error::Unspecified);
            }

            openssl_cvt!(openssl_sys::EVP_PKEY_derive(ctx.0, out.as_mut_ptr(), &mut len));

            if len != out.len() {
                return Err(error::Unspecified);
            }

            Ok(())
        }
    }

    pub fn sign(&self, hash: &MdRef, message: &[u8], sig: &mut [u8]) -> Result<usize, error::Unspecified> {
        unsafe {
            let mut ctx = openssl::md_ctx::MdCtx::new().map_err(|_| error::Unspecified)?;

            openssl_cvt!(openssl_sys::EVP_DigestSignInit(
                ctx.as_ptr(),
                ptr::null_mut(),
                hash.as_ptr(),
                ptr::null_mut(),
                self.pkey
            ));

            let mut sig_len = sig.len();

            openssl_cvt!(openssl_sys::EVP_DigestSign(
                ctx.as_ptr(),
                sig.as_mut_ptr().cast(),
                &mut sig_len,
                message.as_ptr().cast(),
                message.len()
            ));

            Ok(sig_len)
        }
    }
}

impl Drop for PrivateKey {
    fn drop(&mut self) {
        unsafe {
            openssl_sys::EVP_PKEY_free(self.pkey);
        }
    }
}

struct ScopeGuard<T: Copy>(T, fn(T));

impl<T: Copy> ScopeGuard<T> {
    fn into_inner(self) -> T {
        let t = self.0;
        core::mem::forget(self);
        t
    }
}

impl<T: Copy> Drop for ScopeGuard<T> {
    fn drop(&mut self) {
        (self.1)(self.0);
    }
}
