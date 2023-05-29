use secp256k1::{Secp256k1, SecretKey, Message, KeyPair, schnorr::Signature};
use crate::{hash::sha256, RandomNumberGenerator};

/// Compute a tagged hash as defined in BIP-340.
///
/// SHA256(SHA256(tag)||SHA256(tag)||msg)
fn tagged_sha256<D1, D2>(msg: D1, tag: D2) -> [u8; 32]
    where D1: AsRef<[u8]>,
          D2: AsRef<[u8]>
{
    let mut tag_hash = sha256(tag.as_ref()).to_vec();
    tag_hash.extend(tag_hash.clone());
    tag_hash.extend(msg.as_ref());
    sha256(tag_hash)
}

pub fn schnorr_sign<D1, D2, D3>(message: D1, tag: D2, ecdsa_private_key: D3) -> Vec<u8>
    where D1: AsRef<[u8]>,
          D2: AsRef<[u8]>,
          D3: AsRef<[u8]>
{
    schnorr_sign_using(message, tag, ecdsa_private_key, &mut crate::SecureRandomNumberGenerator)
}

pub fn schnorr_sign_using<D1, D2, D3>(message: D1, tag: D2, ecdsa_private_key: D3, rng: &mut impl RandomNumberGenerator) -> Vec<u8>
    where D1: AsRef<[u8]>,
          D2: AsRef<[u8]>,
          D3: AsRef<[u8]>
{
    let mut secp = Secp256k1::new();
    let seed: [u8; 32] = rng.random_data(32).try_into().unwrap();
    secp.seeded_randomize(&seed);
    let sk = SecretKey::from_slice(ecdsa_private_key.as_ref())
        .expect("32 bytes, within curve order");
    let hash = tagged_sha256(message.as_ref(), tag.as_ref());
    let msg = Message::from_slice(&hash)
        .expect("Message hash must be 32 bytes");
    let keypair = KeyPair::from_secret_key(&secp, &sk);
    let aux_rand: [u8; 32] = rng.random_data(32).try_into().unwrap();
    let sig: Signature = secp.sign_schnorr_with_aux_rand(&msg, &keypair, &aux_rand);
    sig.as_ref().to_vec()
}


#[cfg(test)]
mod tests {
    use crate::{make_fake_random_number_generator, schnorr_sign_using, ecdsa_new_private_key_using};

    use super::tagged_sha256;
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
        let sig = schnorr_sign_using(b"Hello", b"World", private_key, &mut rng);
        assert_eq!(sig.len(), 64);
        assert_eq!(sig, hex!("d7488b8f2107c468b4c75a59f9cf1f9945fe7742229a186baa005dcfd434720183958fde5aa34045fea71793710e56b160cf74400b90580ed58ce95d8fa92b45"));
    }
}
