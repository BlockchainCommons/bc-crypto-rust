use sha2::{Digest, Sha256, Sha512};
use hmac::{Hmac, Mac};
use pbkdf2::pbkdf2_hmac;
use hkdf::Hkdf;

pub const CRC32_SIZE: usize = 4;
pub const SHA256_SIZE: usize = 32;
pub const SHA512_SIZE: usize = 64;

/// Computes the CRC-32 checksum of the given data.
pub fn crc32(data: impl AsRef<[u8]>) -> u32 {
    crc32fast::hash(data.as_ref())
}

/// Computes the SHA-256 hash of the given data, returning the hash as a
/// 4-byte vector that can be returned in either big-endian or little-endian format.
pub fn crc32_data_opt(data: impl AsRef<[u8]>, little_endian: bool) -> [u8; CRC32_SIZE] {
    let checksum: u32 = crc32(data);
    let mut result = [0u8; 4];
    if little_endian {
        result.copy_from_slice(&checksum.to_le_bytes());
    } else {
        result.copy_from_slice(&checksum.to_be_bytes());
    }
    result
}
/// Computes the SHA-256 hash of the given data, returning the hash as a
/// 4-byte vector in big-endian format.
pub fn crc32_data(data: impl AsRef<[u8]>) -> [u8; CRC32_SIZE] {
    crc32_data_opt(data, false)
}

/// Computes the SHA-256 digest of the input buffer.
pub fn sha256(data: impl AsRef<[u8]>) -> [u8; SHA256_SIZE] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut hash = [0; 32];
    hash.copy_from_slice(&result);
    hash
}

/// Computes the double SHA-256 digest of the input buffer.
pub fn double_sha256(message: &[u8]) -> [u8; SHA256_SIZE] {
    sha256(sha256(message))
}

/// Computes the SHA-512 digest of the input buffer.
pub fn sha512(data: impl AsRef<[u8]>) -> [u8; SHA512_SIZE] {
    let mut hasher = Sha512::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut hash = [0; 64];
    hash.copy_from_slice(&result);
    hash
}

/// Computes the HMAC-SHA-256 for the given key and message.
pub fn hmac_sha256(key: impl AsRef<[u8]>, message: impl AsRef<[u8]>) -> [u8; SHA256_SIZE] {
    let mut mac = Hmac::<Sha256>::new_from_slice(key.as_ref()).unwrap();
    mac.update(message.as_ref());
    let result = mac.finalize();
    result.into_bytes().into()
}

/// Computes the HMAC-SHA-512 for the given key and message.
pub fn hmac_sha512(key: impl AsRef<[u8]>, message: impl AsRef<[u8]>) -> [u8; SHA512_SIZE] {
    let mut mac = Hmac::<Sha512>::new_from_slice(key.as_ref()).unwrap();
    mac.update(message.as_ref());
    let result = mac.finalize();
    result.into_bytes().into()
}

/// Computes the PBKDF2-HMAC-SHA-256 for the given password.
pub fn pbkdf2_hmac_sha256(pass: impl AsRef<[u8]>, salt: impl AsRef<[u8]>, iterations: u32, key_len: usize) -> Vec<u8> {
    let mut key = vec![0u8; key_len];
    pbkdf2_hmac::<Sha256>(pass.as_ref(), salt.as_ref(), iterations, &mut key);
    key
}

/// Computes the PBKDF2-HMAC-SHA-512 for the given password.
pub fn pbkdf2_hmac_sha512(pass: impl AsRef<[u8]>, salt: impl AsRef<[u8]>, iterations: u32, key_len: usize) -> Vec<u8> {
    let mut key = vec![0u8; key_len];
    pbkdf2_hmac::<Sha512>(pass.as_ref(), salt.as_ref(), iterations, &mut key);
    key
}

/// Computes the HKDF-HMAC-SHA-256 for the given key material.
pub fn hkdf_hmac_sha256(key_material: impl AsRef<[u8]>, salt: impl AsRef<[u8]>, key_len: usize) -> Vec<u8> {
    let mut key = vec![0u8; key_len];
    let hkdf = Hkdf::<Sha256>::new(Some(salt.as_ref()), key_material.as_ref());
    hkdf.expand(&[], &mut key).unwrap();
    key
}

/// Computes the HKDF-HMAC-SHA-512 for the given key material.
pub fn hkdf_hmac_sha512(key_material: impl AsRef<[u8]>, salt: impl AsRef<[u8]>, key_len: usize) -> Vec<u8> {
    let mut key = vec![0u8; key_len];
    let hkdf = Hkdf::<Sha512>::new(Some(salt.as_ref()), key_material.as_ref());
    hkdf.expand(&[], &mut key).unwrap();
    key
}

#[cfg(test)]
mod tests {
    use hex_literal::hex;

    use crate::hash::{sha256, sha512, hmac_sha256, hmac_sha512, pbkdf2_hmac_sha256, crc32, crc32_data, crc32_data_opt};

    #[test]
    fn test_crc32() {
        let input = "Hello, world!".as_bytes();
        assert_eq!(crc32(input), 0xebe6c6e6);
        assert_eq!(crc32_data(input), hex!("ebe6c6e6"));
        assert_eq!(crc32_data_opt(input, true), hex!("e6c6e6eb"));
    }

    #[test]
    fn test_sha256() {
        let input = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
        let expected =
            hex!("248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
        let result = sha256(input.as_bytes());
        assert_eq!(result, expected);
    }

    #[test]
    fn test_sha512() {
        let input = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
        let expected = hex!(
            "204a8fc6dda82f0a0ced7beb8e08a41657c16ef468b228a8279be331a703c33596fd15c13b1b07f9aa1d3bea57789ca031ad85c7a71dd70354ec631238ca3445");
            let result = sha512(input.as_bytes());
            assert_eq!(result, expected);
    }

    #[test]
    fn test_hmac_sha() {
        let key = hex!("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        let message = b"Hi There";
        assert_eq!(hmac_sha256(key, message), hex!("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"));
        assert_eq!(hmac_sha512(key, message), hex!("87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854"));
    }

    #[test]
    fn test_pbkdf2_hmac_sha256() {
        assert_eq!(pbkdf2_hmac_sha256("password", "salt", 1, 32), hex!("120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b"));
    }

    #[test]
    fn test_hkdf_hmac_sha256() {
        let key_material = b"hello";
        let salt = hex!("8e94ef805b93e683ff18");
        assert_eq!(super::hkdf_hmac_sha256(key_material, salt, 32), hex!("13485067e21af17c0900f70d885f02593c0e61e46f86450e4a0201a54c14db76"));
    }
}
