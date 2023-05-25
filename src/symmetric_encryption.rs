use chacha20poly1305::{ChaCha20Poly1305, KeyInit, AeadInPlace};

use crate::CryptoError;

pub fn encrypt_aead_chacha20_poly1305_with_aad<D1, D2, D3, D4>(
    plaintext: D1,
    key: D2,
    nonce: &D3,
    aad: &D4
) -> (Vec<u8>, Vec<u8>)
    where
        D1: AsRef<[u8]>,
        D2: AsRef<[u8]>,
        D3: AsRef<[u8]>,
        D4: AsRef<[u8]>,
{
    let cipher = ChaCha20Poly1305::new(key.as_ref().into());
    let mut buffer = plaintext.as_ref().to_vec();
    let auth = cipher.encrypt_in_place_detached(nonce.as_ref().into(), aad.as_ref(), &mut buffer).unwrap();
    (buffer, auth.to_vec())
}

pub fn encrypt_aead_chacha20_poly1305<D1, D2, D3>(
    plaintext: D1,
    key: D2,
    nonce: &D3
) -> (Vec<u8>, Vec<u8>)
    where
        D1: AsRef<[u8]>,
        D2: AsRef<[u8]>,
        D3: AsRef<[u8]>,
{
    encrypt_aead_chacha20_poly1305_with_aad(plaintext, key, nonce, &[])
}

pub fn decrypt_aead_chacha20_poly1305_with_aad<D1, D2, D3, D4, D5>(
    ciphertext: D1,
    key: D2,
    nonce: D3,
    aad: D4,
    auth: D5
) -> Result<Vec<u8>, CryptoError>
    where
        D1: AsRef<[u8]>,
        D2: AsRef<[u8]>,
        D3: AsRef<[u8]>,
        D4: AsRef<[u8]>,
        D5: AsRef<[u8]>,
{
    let cipher = ChaCha20Poly1305::new(key.as_ref().into());
    let mut buffer = ciphertext.as_ref().to_vec();
    cipher.decrypt_in_place_detached(nonce.as_ref().into(), aad.as_ref(), &mut buffer, auth.as_ref().into()).map_err(|_| CryptoError::DecryptFailed)?;
    Ok(buffer)
}

pub fn decrypt_aead_chacha20_poly1305<D1, D2, D3, D4>(
    ciphertext: D1,
    key: D2,
    nonce: D3,
    auth: D4
) -> Result<Vec<u8>, CryptoError>
    where
        D1: AsRef<[u8]>,
        D2: AsRef<[u8]>,
        D3: AsRef<[u8]>,
        D4: AsRef<[u8]>,
{
    decrypt_aead_chacha20_poly1305_with_aad(ciphertext, key, nonce, [], auth)
}

#[cfg(test)]
mod tests {
    use hex_literal::hex;
    use super::{encrypt_aead_chacha20_poly1305_with_aad, decrypt_aead_chacha20_poly1305_with_aad};
    use crate::random_data;

    const PLAINTEXT: &[u8] = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
    const AAD: [u8; 12] = hex!("50515253c0c1c2c3c4c5c6c7");
    const KEY: [u8; 32] = hex!("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
    const NONCE: [u8; 12] = hex!("070000004041424344454647");
    const CIPHERTEXT: [u8; 114] = hex!("d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116");
    const AUTH: [u8; 16] = hex!("1ae10b594f09e26a7e902ecbd0600691");

    fn encrypted() -> (Vec<u8>, Vec<u8>) {
        encrypt_aead_chacha20_poly1305_with_aad(PLAINTEXT, KEY, &NONCE, &AAD)
    }

    #[test]
    fn test_rfc_test_vector() {
        let (ciphertext, auth) = encrypted();
        assert_eq!(ciphertext, CIPHERTEXT);
        assert_eq!(auth, AUTH);

        let decrypted_plaintext = decrypt_aead_chacha20_poly1305_with_aad(&ciphertext, KEY, NONCE, AAD, &auth).unwrap();
        assert_eq!(PLAINTEXT, decrypted_plaintext.as_slice());
    }

    #[test]
    fn test_random_key_and_nonce() {
        let key = random_data(32);
        let nonce = random_data(12);
        let (ciphertext, auth) = encrypt_aead_chacha20_poly1305_with_aad(PLAINTEXT, &key, &nonce, &AAD);
        let decrypted_plaintext = decrypt_aead_chacha20_poly1305_with_aad(ciphertext, &key, &nonce, AAD, auth).unwrap();
        assert_eq!(PLAINTEXT, decrypted_plaintext.as_slice());
    }

    #[test]
    fn test_empty_data() {
        let key = random_data(32);
        let nonce = random_data(12);
        let (ciphertext, auth) = encrypt_aead_chacha20_poly1305_with_aad([], &key, &nonce, &[]);
        let decrypted_plaintext = decrypt_aead_chacha20_poly1305_with_aad(ciphertext, &key, &nonce, [], auth).unwrap();
        assert_eq!(Vec::<u8>::new(), decrypted_plaintext.as_slice());
    }
}
