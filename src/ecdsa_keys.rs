use bc_rand::RandomNumberGenerator;
use secp256k1::{
    Keypair, PublicKey, Secp256k1, SecretKey,
    constants::{
        PUBLIC_KEY_SIZE, SECRET_KEY_SIZE, UNCOMPRESSED_PUBLIC_KEY_SIZE,
    },
};

pub const ECDSA_PRIVATE_KEY_SIZE: usize = 32;
pub const ECDSA_PUBLIC_KEY_SIZE: usize = 33;
pub const ECDSA_UNCOMPRESSED_PUBLIC_KEY_SIZE: usize = 65;
pub const ECDSA_MESSAGE_HASH_SIZE: usize = 32;
pub const ECDSA_SIGNATURE_SIZE: usize = 64;
pub const SCHNORR_PUBLIC_KEY_SIZE: usize = 32;

use crate::hash::hkdf_hmac_sha256;

/// Generate a new ECDSA private key using the given random number generator.
pub fn ecdsa_new_private_key_using(
    rng: &mut impl RandomNumberGenerator,
) -> [u8; SECRET_KEY_SIZE] {
    rng.random_data(ECDSA_PRIVATE_KEY_SIZE).try_into().unwrap()
}

/// Derives the ECDSA public key from the given private key.
pub fn ecdsa_public_key_from_private_key(
    private_key: &[u8; ECDSA_PRIVATE_KEY_SIZE],
) -> [u8; PUBLIC_KEY_SIZE] {
    let secp = Secp256k1::new();
    let private_key = SecretKey::from_slice(private_key)
        .expect("32 bytes, within curve order");
    let public_key = PublicKey::from_secret_key(&secp, &private_key);
    public_key.serialize()
}

/// Decompresses the given ECDSA public key.
///
/// This format is generally deprecated, but is still used in some places.
pub fn ecdsa_decompress_public_key(
    compressed_public_key: &[u8; PUBLIC_KEY_SIZE],
) -> [u8; UNCOMPRESSED_PUBLIC_KEY_SIZE] {
    let public_key = PublicKey::from_slice(compressed_public_key)
        .expect("65 bytes, serialized according to the spec");
    public_key.serialize_uncompressed()
}

/// Compresses the given ECDSA public key.
pub fn ecdsa_compress_public_key(
    uncompressed_public_key: &[u8; UNCOMPRESSED_PUBLIC_KEY_SIZE],
) -> [u8; PUBLIC_KEY_SIZE] {
    let public_key = PublicKey::from_slice(uncompressed_public_key.as_ref())
        .expect("33 bytes, serialized according to the spec");
    public_key.serialize()
}

/// Derives the ECDSA private key from the given key material.
///
/// Uses the HKDF algorithm to derive the private key from the given key
/// material.
pub fn ecdsa_derive_private_key(key_material: impl AsRef<[u8]>) -> Vec<u8> {
    hkdf_hmac_sha256(key_material, "signing".as_bytes(), 32)
}

/// Derives the Schnorr public key from the given private key.
pub fn schnorr_public_key_from_private_key(
    private_key: &[u8; ECDSA_PRIVATE_KEY_SIZE],
) -> [u8; SCHNORR_PUBLIC_KEY_SIZE] {
    let secp = Secp256k1::new();
    let kp: Keypair = Keypair::from_seckey_slice(&secp, private_key).unwrap();
    let (x, _) = kp.x_only_public_key();
    x.serialize()
}

#[cfg(test)]
mod tests {
    use bc_rand::make_fake_random_number_generator;
    use hex_literal::hex;

    use crate::{
        ecdsa_compress_public_key, ecdsa_decompress_public_key,
        ecdsa_derive_private_key, ecdsa_new_private_key_using,
        ecdsa_public_key_from_private_key, schnorr_public_key_from_private_key,
    };

    #[test]
    fn test_ecdsa_keys() {
        let mut rng = make_fake_random_number_generator();
        let private_key = ecdsa_new_private_key_using(&mut rng);
        assert_eq!(
            private_key,
            hex!(
                "7eb559bbbf6cce2632cf9f194aeb50943de7e1cbad54dcfab27a42759f5e2fed"
            )
        );
        let public_key = ecdsa_public_key_from_private_key(&private_key);
        assert_eq!(
            public_key,
            hex!(
                "0271b92b6212a79b9215f1d24efb9e6294a1bedc95b6c8cf187cb94771ca02626b"
            )
        );
        let decompressed = ecdsa_decompress_public_key(&public_key);
        assert_eq!(
            decompressed,
            hex!(
                "0471b92b6212a79b9215f1d24efb9e6294a1bedc95b6c8cf187cb94771ca02626b72325f1f3bb69a44d3f1cb6d1fd488220dd502f49c0b1a46cb91ce3718d8334a"
            )
        );
        let compressed = ecdsa_compress_public_key(&decompressed);
        assert_eq!(compressed, public_key);
        let x_only_public_key =
            schnorr_public_key_from_private_key(&private_key);
        assert_eq!(
            x_only_public_key,
            hex!(
                "71b92b6212a79b9215f1d24efb9e6294a1bedc95b6c8cf187cb94771ca02626b"
            )
        );

        let private_key = ecdsa_derive_private_key(b"password");
        assert_eq!(
            private_key,
            hex!(
                "05cc550daa75058e613e606d9898fedf029e395911c43273a208b7e0e88e271b"
            )
        );
    }
}
