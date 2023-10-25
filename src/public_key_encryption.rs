use crate::{X25519_PRIVATE_KEY_SIZE, X25519_PUBLIC_KEY_SIZE, hash::hkdf_hmac_sha256, SYMMETRIC_KEY_SIZE};
use bc_rand::RandomNumberGenerator;
use x25519_dalek::{PublicKey, StaticSecret};

/// Create a new X25519 private key using the given random number generator.
pub fn x25519_new_agreement_private_key_using(rng: &mut impl RandomNumberGenerator) -> [u8; X25519_PRIVATE_KEY_SIZE] {
    rng.random_data(X25519_PRIVATE_KEY_SIZE).try_into().unwrap()
}

/// Derive a X25519 public key from a private key.
pub fn x25519_agreement_public_key_from_private_key(agreement_private_key: &[u8; X25519_PRIVATE_KEY_SIZE]) -> [u8; X25519_PUBLIC_KEY_SIZE] {
    let sk = StaticSecret::from(*agreement_private_key);
    let pk = PublicKey::from(&sk);
    pk.as_bytes().to_owned()
}

/// Derive an X25519 agreement private key from the given key material.
pub fn x25519_derive_agreement_private_key(key_material: impl AsRef<[u8]>) -> [u8; X25519_PRIVATE_KEY_SIZE] {
    hkdf_hmac_sha256(key_material, "agreement".as_bytes(), X25519_PRIVATE_KEY_SIZE).try_into().unwrap()
}

/// Derive an X25519 signing private key from the given key material.
pub fn x25519_derive_signing_private_key(key_material: impl AsRef<[u8]>) -> [u8; X25519_PRIVATE_KEY_SIZE] {
    hkdf_hmac_sha256(key_material, "signing".as_bytes(), X25519_PRIVATE_KEY_SIZE).try_into().unwrap()
}

/// Compute the shared symmetric key from the given agreement private key and agreement public key.
pub fn x25519_shared_key(agreement_private_key: &[u8; X25519_PRIVATE_KEY_SIZE], agreement_public_key: &[u8; X25519_PUBLIC_KEY_SIZE]) -> [u8; SYMMETRIC_KEY_SIZE] {
    let sk = StaticSecret::from(*agreement_private_key);
    let pk = PublicKey::from(*agreement_public_key);
    let shared_secret = sk.diffie_hellman(&pk);
    hkdf_hmac_sha256(shared_secret.as_bytes(), "agreement".as_bytes(), 32).try_into().unwrap()
}

#[cfg(test)]
mod tests {
    use bc_rand::make_fake_random_number_generator;
    use hex_literal::hex;

    use crate::{x25519_new_agreement_private_key_using, x25519_agreement_public_key_from_private_key, x25519_derive_agreement_private_key, x25519_derive_signing_private_key, x25519_shared_key};

    #[test]
    fn test_x25519_keys() {
        let mut rng = make_fake_random_number_generator();
        let private_key = x25519_new_agreement_private_key_using(&mut rng);
        assert_eq!(private_key, hex!("7eb559bbbf6cce2632cf9f194aeb50943de7e1cbad54dcfab27a42759f5e2fed"));
        let public_key = x25519_agreement_public_key_from_private_key(&private_key);
        assert_eq!(public_key, hex!("f1bd7a7e118ea461eba95126a3efef543ebb78439d1574bedcbe7d89174cf025"));

        let derived_agreement_private_key = x25519_derive_agreement_private_key(b"password");
        assert_eq!(derived_agreement_private_key, hex!("7b19769132648ff43ae60cbaa696d5be3f6d53e6645db72e2d37516f0729619f"));

        let derived_signing_private_key = x25519_derive_signing_private_key(b"password");
        assert_eq!(derived_signing_private_key, hex!("05cc550daa75058e613e606d9898fedf029e395911c43273a208b7e0e88e271b"));
    }

    #[test]
    fn test_key_agreement() {
        let mut rng = make_fake_random_number_generator();
        let alice_private_key = x25519_new_agreement_private_key_using(&mut rng);
        let alice_public_key = x25519_agreement_public_key_from_private_key(&alice_private_key);
        let bob_private_key = x25519_new_agreement_private_key_using(&mut rng);
        let bob_public_key = x25519_agreement_public_key_from_private_key(&bob_private_key);
        let alice_shared_key = x25519_shared_key(&alice_private_key, &bob_public_key);
        let bob_shared_key = x25519_shared_key(&bob_private_key, &alice_public_key);
        assert_eq!(alice_shared_key, bob_shared_key);
        assert_eq!(alice_shared_key, hex!("1e9040d1ff45df4bfca7ef2b4dd2b11101b40d91bf5bf83f8c83d53f0fbb6c23"));
    }
}
