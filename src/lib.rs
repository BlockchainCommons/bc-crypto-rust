#![doc(html_root_url = "https://docs.rs/bc-crypto/0.5.0")]
#![warn(rust_2018_idioms)]

//! # Introduction
//!
//! `bc-crypto` is a exposes a uniform API for the cryptographic primitives used in higher-level [Blockchain Commons](https://blockchaincommons.com) projects such as [Gordian Envelope](https://crates.io/crates/bc-envelope). The various providers listed below may change, but the API this package provides should be stable.
//!
//! | Category | Algorithm | Provider
//! |---|---|---
//! | Cryptographic digest | SHA-256 | [sha2](https://crates.io/crates/sha2)
//! | Cryptographic digest | SHA-512 | [sha2](https://crates.io/crates/sha2)
//! | Hashed Message Authentication Codes | HMAC-SHA-256 | [hmac](https://crates.io/crates/hmac)
//! | Hashed Message Authentication Codes | HMAC-SHA-512 | [hmac](https://crates.io/crates/hmac)
//! | Password Expansion | PBKDF2-HMAC-SHA-256 | [pbkdf2](https://crates.io/crates/pbkdf2)
//! | Key Derivation | HKDF-HMAC-SHA-256 |  [hkdf](https://crates.io/crates/hkdf)
//! | Symmetric Encryption | IETF-ChaCha20-Poly1305 | [chacha20poly1305](https://crates.io/crates/chacha20poly1305)
//! | Key Agreement | X25519 | [x25519-dalek](https://crates.io/crates/x25519-dalek)
//! | Signing/Verification | ECDSA | [secp256k1](https://crates.io/crates/secp256k1)
//! | Signing/Verification | Schnorr | [secp256k1](https://crates.io/crates/secp256k1)
//! | Secure Random Number Generation | NA | [getrandom](https://crates.io/crates/getrandom), [rand](https://crates.io/crates/rand)
//! | Pseudorandom Number Generation | Xoshiro256** | [rand_xoshiro](https://crates.io/crates/rand_xoshiro)
//!
//! # Getting Started
//!
//! ```toml
//! [dependencies]
//! bc-crypto = "0.5.0"
//! ```

pub const CRC32_SIZE: usize = 4;
pub const SHA256_SIZE: usize = 32;
pub const SHA512_SIZE: usize = 64;
pub const SYMMETRIC_KEY_SIZE: usize = 32;
pub const SYMMETRIC_NONCE_SIZE: usize = 12;
pub const SYMMETRIC_AUTH_SIZE: usize = 16;
pub const ECDSA_PRIVATE_KEY_SIZE: usize = 32;
pub const ECDSA_PUBLIC_KEY_SIZE: usize = 33;
pub const ECDSA_UNCOMPRESSED_PUBLIC_KEY_SIZE: usize = 65;
pub const ECDSA_MESSAGE_HASH_SIZE: usize = 32;
pub const ECDSA_SIGNATURE_SIZE : usize = 64;
pub const SCHNORR_PUBLIC_KEY_SIZE: usize = 32;
pub const SCHNORR_SIGNATURE_SIZE: usize = 64;
pub const X25519_PRIVATE_KEY_SIZE: usize = 32;
pub const X25519_PUBLIC_KEY_SIZE: usize = 32;

/// The `hash` module contains functions for hashing data.
pub mod hash;

mod memzero;
pub use memzero::{memzero, memzero_vec_vec_u8};

mod symmetric_encryption;
pub use symmetric_encryption::{
    aead_chacha20_poly1305_encrypt_with_aad,
    aead_chacha20_poly1305_encrypt,
    aead_chacha20_poly1305_decrypt_with_aad,
    aead_chacha20_poly1305_decrypt
};

mod public_key_encryption;
pub use public_key_encryption:: {
    x25519_new_agreement_private_key_using,
    x25519_agreement_public_key_from_private_key,
    x25519_derive_agreement_private_key,
    x25519_derive_signing_private_key,
    x25519_shared_key,
};

mod ecdsa_keys;
pub use ecdsa_keys::{
    ecdsa_new_private_key_using,
    ecdsa_public_key_from_private_key,
    ecdsa_decompress_public_key,
    ecdsa_compress_public_key,
    ecdsa_derive_private_key,
    schnorr_public_key_from_private_key,
};

mod ecdsa_signing;
pub use ecdsa_signing::{
    ecdsa_sign,
    ecdsa_verify,
};

mod schnorr_signing;
pub use schnorr_signing::{
    schnorr_sign,
    schnorr_sign_using,
    schnorr_sign_with_aux_rand,
    schnorr_verify,
};

mod error;
pub use error::Error;

#[cfg(test)]
mod tests {
    #[test]
    fn test_readme_deps() {
        version_sync::assert_markdown_deps_updated!("README.md");
    }

    #[test]
    fn test_html_root_url() {
        version_sync::assert_html_root_url_updated!("src/lib.rs");
    }
}
