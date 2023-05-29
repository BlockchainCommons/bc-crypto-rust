use secp256k1::{Secp256k1, SecretKey, PublicKey};

use crate::{ECDSA_PRIVATE_KEY_LENGTH, RandomNumberGenerator, SecureRandomNumberGenerator};

pub fn ecdsa_new_private_key() -> Vec<u8> {
    ecdsa_new_private_key_using(&mut SecureRandomNumberGenerator)
}

pub fn ecdsa_new_private_key_using(rng: &mut impl RandomNumberGenerator) -> Vec<u8> {
    rng.random_data(ECDSA_PRIVATE_KEY_LENGTH)
}

pub fn ecdsa_derive_public_key(private_key: &[u8]) -> Vec<u8> {
    let secp = Secp256k1::new();
    let private_key = SecretKey::from_slice(private_key)
        .expect("32 bytes, within curve order");
    let public_key = PublicKey::from_secret_key(&secp, &private_key);
    public_key.serialize().to_vec()
}
