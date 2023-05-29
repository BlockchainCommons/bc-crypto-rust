use secp256k1::{Secp256k1, SecretKey, PublicKey};

use crate::{ECDSA_PRIVATE_KEY_LENGTH, RandomNumberGenerator, SecureRandomNumberGenerator, hash::hkdf_hmac_sha256};

pub fn ecdsa_new_private_key() -> Vec<u8> {
    ecdsa_new_private_key_using(&mut SecureRandomNumberGenerator)
}

pub fn ecdsa_new_private_key_using(rng: &mut impl RandomNumberGenerator) -> Vec<u8> {
    rng.random_data(ECDSA_PRIVATE_KEY_LENGTH)
}

pub fn ecdsa_derive_public_key<D>(private_key: D) -> Vec<u8>
    where D: AsRef<[u8]>
{
    let secp = Secp256k1::new();
    let private_key = SecretKey::from_slice(private_key.as_ref())
        .expect("32 bytes, within curve order");
    let public_key = PublicKey::from_secret_key(&secp, &private_key);
    public_key.serialize().to_vec()
}

pub fn ecdsa_decompress_public_key<D>(compressed_public_key: D) -> Vec<u8>
    where D: AsRef<[u8]>
{
    let public_key = PublicKey::from_slice(compressed_public_key.as_ref())
        .expect("65 bytes, serialized according to the spec");
    let public_key = public_key.serialize_uncompressed();
    public_key.to_vec()
}

pub fn ecdsa_compress_public_key<D>(uncompressed_public_key: D) -> Vec<u8>
    where D: AsRef<[u8]>
{
    let public_key = PublicKey::from_slice(uncompressed_public_key.as_ref())
        .expect("33 bytes, serialized according to the spec");
    let public_key = public_key.serialize();
    public_key.to_vec()
}

pub fn ecdsa_derive_private_key<D>(key_material: D) -> Vec<u8>
    where D: AsRef<[u8]>
{
    hkdf_hmac_sha256(key_material, "signing".as_bytes(), 32)
}

#[cfg(test)]
mod tests {
    use crate::{ecdsa_derive_public_key, make_fake_random_number_generator, ecdsa_new_private_key_using, ecdsa_decompress_public_key, ecdsa_compress_public_key};
    use hex_literal::hex;

    #[test]
    fn test_ecdsa_keys() {
        let mut rng = make_fake_random_number_generator();
        let private_key = ecdsa_new_private_key_using(&mut rng);
        assert_eq!(private_key, hex!("7eb559bbbf6cce2632cf9f194aeb50943de7e1cbad54dcfab27a42759f5e2fed"));
        let public_key = ecdsa_derive_public_key(&private_key);
        assert_eq!(public_key, hex!("0271b92b6212a79b9215f1d24efb9e6294a1bedc95b6c8cf187cb94771ca02626b"));
        let decompressed = ecdsa_decompress_public_key(&public_key);
        assert_eq!(decompressed, hex!("0471b92b6212a79b9215f1d24efb9e6294a1bedc95b6c8cf187cb94771ca02626b72325f1f3bb69a44d3f1cb6d1fd488220dd502f49c0b1a46cb91ce3718d8334a"));
        let compressed = ecdsa_compress_public_key(&decompressed);
        assert_eq!(compressed, public_key);
    }
}
