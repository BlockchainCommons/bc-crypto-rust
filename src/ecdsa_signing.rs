use secp256k1::{SecretKey, Secp256k1, PublicKey, Message, ecdsa::Signature};
use crate::{ECDSA_PRIVATE_KEY_LENGTH, RandomNumberGenerator, SecureRandomNumberGenerator, hash::double_sha256};

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

pub fn ecdsa_sign(private_key: &[u8], message: &[u8]) -> Vec<u8> {
    let secp = Secp256k1::new();
    let sk = SecretKey::from_slice(private_key)
        .expect("32 bytes, within curve order");
    let hash = double_sha256(message);
    let msg = Message::from_slice(&hash)
        .expect("Message hash must be 32 bytes");
    let sig = secp.sign_ecdsa(&msg, &sk);
    sig.serialize_compact().to_vec()
}

pub fn ecdsa_verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
    let secp = Secp256k1::new();
    let pk = PublicKey::from_slice(public_key)
        .expect("33 or 65 bytes, serialized according to the spec");
    let hash = double_sha256(message);
    let msg = Message::from_slice(&hash)
        .expect("Message hash must be 32 bytes");
    let sig = Signature::from_compact(signature)
        .expect("64 bytes, signature according to the spec");
    secp.verify_ecdsa(&msg, &sig, &pk).is_ok()
}

#[cfg(test)]
mod tests {
    use crate::{ecdsa_derive_public_key, ECDSA_PRIVATE_KEY_LENGTH, ECDSA_PUBLIC_KEY_LENGTH, make_fake_random_number_generator, ecdsa_new_private_key_using, ecdsa_sign, ecdsa_verify};
    use hex_literal::hex;

    const MESSAGE: &[u8] = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";

    #[test]
    fn test_1() {
        let mut rng = make_fake_random_number_generator();
        let private_key = ecdsa_new_private_key_using(&mut rng);
        //println!("private_key: {}", hex::encode(&private_key));
        assert_eq!(private_key.len(), ECDSA_PRIVATE_KEY_LENGTH);
        assert_eq!(private_key, hex!("7eb559bbbf6cce2632cf9f194aeb50943de7e1cbad54dcfab27a42759f5e2fed"));
        let public_key = ecdsa_derive_public_key(&private_key);
        // println!("public_key: {}", hex::encode(&public_key));
        assert_eq!(public_key.len(), ECDSA_PUBLIC_KEY_LENGTH);
        assert_eq!(public_key, hex!("0271b92b6212a79b9215f1d24efb9e6294a1bedc95b6c8cf187cb94771ca02626b"));

        // println!("digest: {}", hex::encode(super::double_sha256(MESSAGE)));
        let signature = ecdsa_sign(&private_key, MESSAGE);
        // println!("signature: {}", hex::encode(&signature));
        assert_eq!(signature.len(), 64);
        assert_eq!(signature, hex!("e75702ed8f645ce7fe510507b2403029e461ef4570d12aa440e4f81385546a13740b7d16878ff0b46b1cbe08bc218ccb0b00937b61c4707de2ca6148508e51fb"));
        assert!(ecdsa_verify(&public_key, MESSAGE, &signature));
    }
}
