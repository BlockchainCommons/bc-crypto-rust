use secp256k1::{SecretKey, Secp256k1, PublicKey, Message, ecdsa::Signature};
use crate::{hash::double_sha256, ECDSA_PRIVATE_KEY_SIZE, ECDSA_PUBLIC_KEY_SIZE, ECDSA_SIGNATURE_SIZE};

pub fn ecdsa_sign<T>(private_key: &[u8; ECDSA_PRIVATE_KEY_SIZE], message: T) -> [u8; ECDSA_SIGNATURE_SIZE]
    where T: AsRef<[u8]>,
{
    let secp = Secp256k1::new();
    let sk = SecretKey::from_slice(private_key).expect("32 bytes, within curve order");
    let hash = double_sha256(message.as_ref());
    let msg = Message::from_slice(&hash).unwrap();
    let sig = secp.sign_ecdsa(&msg, &sk);
    sig.serialize_compact().to_vec().try_into().unwrap()
}

pub fn ecdsa_verify<T>(public_key: &[u8; ECDSA_PUBLIC_KEY_SIZE], message: T, signature: &[u8; ECDSA_SIGNATURE_SIZE]) -> bool
    where T: AsRef<[u8]>,
{
    let secp = Secp256k1::new();
    let pk = PublicKey::from_slice(public_key)
        .expect("33 or 65 bytes, serialized according to the spec");
    let hash = double_sha256(message.as_ref());
    let msg = Message::from_slice(&hash)
        .expect("Message hash must be 32 bytes");
    let sig = Signature::from_compact(signature)
        .expect("64 bytes, signature according to the spec");
    secp.verify_ecdsa(&msg, &sig, &pk).is_ok()
}

#[cfg(test)]
mod tests {
    use crate::{ecdsa_public_key_from_private_key, ecdsa_sign, ecdsa_verify, make_fake_random_number_generator, ecdsa_new_private_key_using};
    use hex_literal::hex;

    const MESSAGE: &[u8] = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";

    #[test]
    fn test_ecdsa_signing() {
        let mut rng = make_fake_random_number_generator();
        let private_key = ecdsa_new_private_key_using(&mut rng);
        let public_key = ecdsa_public_key_from_private_key(&private_key);
        let signature = ecdsa_sign(&private_key, MESSAGE);
        assert_eq!(signature, hex!("e75702ed8f645ce7fe510507b2403029e461ef4570d12aa440e4f81385546a13740b7d16878ff0b46b1cbe08bc218ccb0b00937b61c4707de2ca6148508e51fb"));
        assert!(ecdsa_verify(&public_key, MESSAGE, &signature));
    }
}
