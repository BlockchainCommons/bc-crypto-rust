use chacha20poly1305::aead::rand_core::CryptoRngCore;
use ed25519_dalek::{Signature, SigningKey, ed25519::signature::Signer};

pub const ED25519_PUBLIC_KEY_SIZE: usize = ed25519_dalek::PUBLIC_KEY_LENGTH;
pub const ED25519_PRIVATE_KEY_SIZE: usize = ed25519_dalek::SECRET_KEY_LENGTH;
pub const ED25519_SIGNATURE_SIZE: usize = ed25519_dalek::SIGNATURE_LENGTH;

pub fn ed25519_new_private_key_using(
    rng: &mut impl CryptoRngCore,
) -> [u8; ED25519_PRIVATE_KEY_SIZE] {
    SigningKey::generate(rng).to_bytes()
}

pub fn ed25519_public_key_from_private_key(
    private_key: &[u8; ED25519_PRIVATE_KEY_SIZE],
) -> [u8; ED25519_PUBLIC_KEY_SIZE] {
    let signing_key = SigningKey::from_bytes(private_key);
    signing_key.verifying_key().to_bytes()
}

pub fn ed25519_sign(
    private_key: &[u8; ED25519_PRIVATE_KEY_SIZE],
    message: &[u8],
) -> [u8; ED25519_SIGNATURE_SIZE] {
    let signing_key = SigningKey::from_bytes(private_key);
    signing_key.try_sign(message).unwrap().to_bytes()
}

pub fn ed25519_verify(
    public_key: &[u8; ED25519_PUBLIC_KEY_SIZE],
    message: &[u8],
    signature: &[u8; ED25519_SIGNATURE_SIZE],
) -> bool {
    let verifying_key =
        ed25519_dalek::VerifyingKey::from_bytes(public_key).unwrap();
    let signature = Signature::from_bytes(signature);
    verifying_key.verify_strict(message, &signature).is_ok()
}

#[cfg(test)]
mod tests {
    use hex_literal::hex;

    use crate::{
        ED25519_PRIVATE_KEY_SIZE, ED25519_PUBLIC_KEY_SIZE,
        ED25519_SIGNATURE_SIZE, ed25519_public_key_from_private_key,
        ed25519_sign, ed25519_verify,
    };

    #[test]
    fn test_ed25519_signing() {
        use bc_rand::fake_random_data;

        const MESSAGE: &[u8] = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";

        // Generate deterministic random bytes for the private key
        let private_key: [u8; ED25519_PRIVATE_KEY_SIZE] =
            fake_random_data(ED25519_PRIVATE_KEY_SIZE)
                .try_into()
                .unwrap();
        assert_eq!(
            private_key,
            hex!(
                "7eb559bbbf6cce2632cf9f194aeb50943de7e1cbad54dcfab27a42759f5e2fed"
            )
        );
        let public_key = ed25519_public_key_from_private_key(&private_key);
        assert_eq!(
            public_key,
            hex!(
                "76f863e1024d8ff6cd8ad56c434e01dbbf2999cfc2f132fc7f41ca19fed7a97c"
            )
        );
        let signature = ed25519_sign(&private_key, MESSAGE);
        assert_eq!(
            signature,
            hex!(
                "647cc65243e8a61dc273242b13008994e4658a7e0bcbb1fd621b01dad2ddf7577901c4c4d4ea484ae5ca3172c4b8a75877bd7d5349a7055acdc023b04fcd0406"
            )
        );
        assert!(ed25519_verify(&public_key, MESSAGE, &signature));
    }

    #[test]
    fn test_ed25519_vectors() {
        struct TestVector {
            secret_key: [u8; ED25519_PRIVATE_KEY_SIZE],
            public_key: [u8; ED25519_PUBLIC_KEY_SIZE],
            message: Vec<u8>,
            signature: [u8; ED25519_SIGNATURE_SIZE],
        }

        // Test vectors from RFC 8032
        // https://www.rfc-editor.org/rfc/rfc8032#page-24
        let test_vectors = [
            TestVector {
                secret_key: hex!("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"),
                public_key: hex!("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"),
                message: hex!("").to_vec(),
                signature: hex!("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b")
            },
            TestVector {
                secret_key: hex!("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb"),
                public_key: hex!("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"),
                message: hex!("72").to_vec(),
                signature: hex!("92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00")
            },
            TestVector {
                secret_key: hex!("c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7"),
                public_key: hex!("fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025"),
                message: hex!("af82").to_vec(),
                signature: hex!("6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a")
            },
            TestVector {
                secret_key: hex!("f5e5767cf153319517630f226876b86c8160cc583bc013744c6bf255f5cc0ee5"),
                public_key: hex!("278117fc144c72340f67d0f2316e8386ceffbf2b2428c9c51fef7c597f1d426e"),
                message: hex!("08b8b2b733424243760fe426a4b54908632110a66c2f6591eabd3345e3e4eb98fa6e264bf09efe12ee50f8f54e9f77b1e355f6c50544e23fb1433ddf73be84d879de7c0046dc4996d9e773f4bc9efe5738829adb26c81b37c93a1b270b20329d658675fc6ea534e0810a4432826bf58c941efb65d57a338bbd2e26640f89ffbc1a858efcb8550ee3a5e1998bd177e93a7363c344fe6b199ee5d02e82d522c4feba15452f80288a821a579116ec6dad2b3b310da903401aa62100ab5d1a36553e06203b33890cc9b832f79ef80560ccb9a39ce767967ed628c6ad573cb116dbefefd75499da96bd68a8a97b928a8bbc103b6621fcde2beca1231d206be6cd9ec7aff6f6c94fcd7204ed3455c68c83f4a41da4af2b74ef5c53f1d8ac70bdcb7ed185ce81bd84359d44254d95629e9855a94a7c1958d1f8ada5d0532ed8a5aa3fb2d17ba70eb6248e594e1a2297acbbb39d502f1a8c6eb6f1ce22b3de1a1f40cc24554119a831a9aad6079cad88425de6bde1a9187ebb6092cf67bf2b13fd65f27088d78b7e883c8759d2c4f5c65adb7553878ad575f9fad878e80a0c9ba63bcbcc2732e69485bbc9c90bfbd62481d9089beccf80cfe2df16a2cf65bd92dd597b0707e0917af48bbb75fed413d238f5555a7a569d80c3414a8d0859dc65a46128bab27af87a71314f318c782b23ebfe808b82b0ce26401d2e22f04d83d1255dc51addd3b75a2b1ae0784504df543af8969be3ea7082ff7fc9888c144da2af58429ec96031dbcad3dad9af0dcbaaaf268cb8fcffead94f3c7ca495e056a9b47acdb751fb73e666c6c655ade8297297d07ad1ba5e43f1bca32301651339e22904cc8c42f58c30c04aafdb038dda0847dd988dcda6f3bfd15c4b4c4525004aa06eeff8ca61783aacec57fb3d1f92b0fe2fd1a85f6724517b65e614ad6808d6f6ee34dff7310fdc82aebfd904b01e1dc54b2927094b2db68d6f903b68401adebf5a7e08d78ff4ef5d63653a65040cf9bfd4aca7984a74d37145986780fc0b16ac451649de6188a7dbdf191f64b5fc5e2ab47b57f7f7276cd419c17a3ca8e1b939ae49e488acba6b965610b5480109c8b17b80e1b7b750dfc7598d5d5011fd2dcc5600a32ef5b52a1ecc820e308aa342721aac0943bf6686b64b2579376504ccc493d97e6aed3fb0f9cd71a43dd497f01f17c0e2cb3797aa2a2f256656168e6c496afc5fb93246f6b1116398a346f1a641f3b041e989f7914f90cc2c7fff357876e506b50d334ba77c225bc307ba537152f3f1610e4eafe595f6d9d90d11faa933a15ef1369546868a7f3a45a96768d40fd9d03412c091c6315cf4fde7cb68606937380db2eaaa707b4c4185c32eddcdd306705e4dc1ffc872eeee475a64dfac86aba41c0618983f8741c5ef68d3a101e8a3b8cac60c905c15fc910840b94c00a0b9d0").to_vec(),
                signature: hex!("0aab4c900501b3e24d7cdf4663326a3a87df5e4843b2cbdb67cbf6e460fec350aa5371b1508f9f4528ecea23c436d94b5e8fcd4f681e30a6ac00a9704a188a03")
            },
        ];

        for test_vector in test_vectors.iter() {
            assert_eq!(
                ed25519_public_key_from_private_key(&test_vector.secret_key),
                test_vector.public_key
            );
            assert!(ed25519_verify(
                &test_vector.public_key,
                &test_vector.message,
                &test_vector.signature
            ));
        }
    }
}
