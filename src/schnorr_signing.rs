use bc_rand::{ RandomNumberGenerator, SecureRandomNumberGenerator};
use secp256k1::{Secp256k1, SecretKey, Message, KeyPair, schnorr::Signature, XOnlyPublicKey};
use crate::{hash::sha256, SCHNORR_SIGNATURE_SIZE, SCHNORR_PUBLIC_KEY_SIZE, ECDSA_PRIVATE_KEY_SIZE};

/// Compute a tagged hash as defined in BIP-340.
///
/// SHA256(SHA256(tag)||SHA256(tag)||msg)
fn tagged_sha256(msg: impl AsRef<[u8]>, tag: impl AsRef<[u8]>) -> [u8; 32] {
    let mut tag_hash = sha256(tag.as_ref()).to_vec();
    tag_hash.extend(tag_hash.clone());
    tag_hash.extend(msg.as_ref());
    sha256(tag_hash)
}

/// Schnorr signs the given message using the given private key and user-defined tag.
pub fn schnorr_sign(ecdsa_private_key: &[u8; ECDSA_PRIVATE_KEY_SIZE], message: impl AsRef<[u8]>, tag: impl AsRef<[u8]>) -> [u8; SCHNORR_SIGNATURE_SIZE] {
    let mut rng = SecureRandomNumberGenerator;
    schnorr_sign_using(ecdsa_private_key, message, tag, &mut rng)
}

/// Schnorr signs the given message using the given private key, user-defined tag,
/// and random number generator.
pub fn schnorr_sign_using(
    ecdsa_private_key: &[u8; ECDSA_PRIVATE_KEY_SIZE],
    message: impl AsRef<[u8]>,
    tag: impl AsRef<[u8]>,
    rng: &mut dyn RandomNumberGenerator,
) -> [u8; SCHNORR_SIGNATURE_SIZE] {
    let mut secp = Secp256k1::new();
    let seed: [u8; 32] = rng.random_data(32).try_into().unwrap();
    secp.seeded_randomize(&seed);
    let sk = SecretKey::from_slice(ecdsa_private_key)
        .expect("32 bytes, within curve order");
    let hash = tagged_sha256(message.as_ref(), tag.as_ref());
    let msg = Message::from_slice(&hash)
        .expect("Message hash must be 32 bytes");
    let keypair = KeyPair::from_secret_key(&secp, &sk);
    let aux_rand: [u8; 32] = rng.random_data(32).try_into().unwrap();
    let sig: Signature = secp.sign_schnorr_with_aux_rand(&msg, &keypair, &aux_rand);
    sig.as_ref().to_vec().try_into().unwrap()
}

/// Verifies the given Schnorr signature against the given message, public key,
/// and user-defined tag, which must match the tag used to create the signature.
pub fn schnorr_verify(schnorr_public_key: &[u8; SCHNORR_PUBLIC_KEY_SIZE], schnorr_signature: &[u8; SCHNORR_SIGNATURE_SIZE], message: impl AsRef<[u8]>, tag: impl AsRef<[u8]>) -> bool {
    let secp = Secp256k1::new();
    let hash = tagged_sha256(message.as_ref(), tag.as_ref());
    let msg = Message::from_slice(&hash)
        .expect("Message hash must be 32 bytes");
    let sig = Signature::from_slice(schnorr_signature)
        .expect("Signature must be 64 bytes");
    let pk = XOnlyPublicKey::from_slice(schnorr_public_key)
        .expect("32 bytes, serialized according to the spec");
    secp.verify_schnorr(&sig, &msg, &pk).is_ok()
}


#[cfg(test)]
mod tests {
    use crate::{schnorr_sign_using, ecdsa_new_private_key_using, schnorr_public_key_from_private_key, schnorr_verify};

    use super::tagged_sha256;
    use bc_rand::make_fake_random_number_generator;
    use hex_literal::hex;

    #[test]
    fn test_tagged_sha256() {
        assert_eq!(tagged_sha256(b"Hello", b"World"), hex!("e9f3a975986209830c6797c0e3fda21545360d2055c96b5386b5c5ab7c0cf53e"));
    }

    #[test]
    fn test_schnorr_sign() {
        let mut rng = make_fake_random_number_generator();
        let private_key = ecdsa_new_private_key_using(&mut rng);
        assert_eq!(&private_key, &hex!("7eb559bbbf6cce2632cf9f194aeb50943de7e1cbad54dcfab27a42759f5e2fed"));
        let message = b"Hello";
        let tag = b"World";
        let sig = schnorr_sign_using(&private_key, message, tag, &mut rng);
        assert_eq!(sig.len(), 64);
        assert_eq!(sig, hex!("d7488b8f2107c468b4c75a59f9cf1f9945fe7742229a186baa005dcfd434720183958fde5aa34045fea71793710e56b160cf74400b90580ed58ce95d8fa92b45"));
        let schnorr_public_key = schnorr_public_key_from_private_key(&private_key);
        assert!(schnorr_verify(&schnorr_public_key, &sig, message, tag));
    }
}
