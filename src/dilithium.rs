use anyhow::{Result, anyhow};
use pqcrypto_dilithium::*;
use pqcrypto_traits::sign::{ SecretKey, PublicKey, DetachedSignature };

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DilithiumLevel {
    Dilithium2,
    Dilithium3,
    Dilithium5,
}

impl DilithiumLevel {
    pub fn private_key_size(&self) -> usize {
        match self {
            DilithiumLevel::Dilithium2 => dilithium2::secret_key_bytes(),
            DilithiumLevel::Dilithium3 => dilithium3::secret_key_bytes(),
            DilithiumLevel::Dilithium5 => dilithium5::secret_key_bytes(),
        }
    }

    pub fn public_key_size(&self) -> usize {
        match self {
            DilithiumLevel::Dilithium2 => dilithium2::public_key_bytes(),
            DilithiumLevel::Dilithium3 => dilithium3::public_key_bytes(),
            DilithiumLevel::Dilithium5 => dilithium5::public_key_bytes(),
        }
    }

    pub fn signature_size(&self) -> usize {
        match self {
            DilithiumLevel::Dilithium2 => dilithium2::signature_bytes(),
            DilithiumLevel::Dilithium3 => dilithium3::signature_bytes(),
            DilithiumLevel::Dilithium5 => dilithium5::signature_bytes(),
        }
    }
}

#[derive(Clone, PartialEq)]
pub enum DilithiumPrivateKey {
    Dilithium2(Box<dilithium2::SecretKey>),
    Dilithium3(Box<dilithium3::SecretKey>),
    Dilithium5(Box<dilithium5::SecretKey>),
}

impl DilithiumPrivateKey {
    pub fn level(&self) -> DilithiumLevel {
        match self {
            DilithiumPrivateKey::Dilithium2(_) => DilithiumLevel::Dilithium2,
            DilithiumPrivateKey::Dilithium3(_) => DilithiumLevel::Dilithium3,
            DilithiumPrivateKey::Dilithium5(_) => DilithiumLevel::Dilithium5,
        }
    }

    pub fn size(&self) -> usize {
        self.level().private_key_size()
    }

    pub fn as_bytes(&self) -> &[u8] {
        match self {
            DilithiumPrivateKey::Dilithium2(key) => key.as_bytes(),
            DilithiumPrivateKey::Dilithium3(key) => key.as_bytes(),
            DilithiumPrivateKey::Dilithium5(key) => key.as_bytes(),
        }
    }

    pub fn from_bytes(level: DilithiumLevel, bytes: &[u8]) -> Result<Self> {
        match level {
            DilithiumLevel::Dilithium2 => Ok(DilithiumPrivateKey::Dilithium2(Box::new(dilithium2::SecretKey::from_bytes(bytes).map_err(|e| anyhow!(e))?))),
            DilithiumLevel::Dilithium3 => Ok(DilithiumPrivateKey::Dilithium3(Box::new(dilithium3::SecretKey::from_bytes(bytes).map_err(|e| anyhow!(e))?))),
            DilithiumLevel::Dilithium5 => Ok(DilithiumPrivateKey::Dilithium5(Box::new(dilithium5::SecretKey::from_bytes(bytes).map_err(|e| anyhow!(e))?))),
        }
    }
}

impl std::fmt::Debug for DilithiumPrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DilithiumPrivateKey::Dilithium2(_) => f.write_str("Dilithium2PrivateKey"),
            DilithiumPrivateKey::Dilithium3(_) => f.write_str("Dilithium3PrivateKey"),
            DilithiumPrivateKey::Dilithium5(_) => f.write_str("Dilithium5PrivateKey"),
        }
    }
}

#[derive(Clone, PartialEq)]
pub enum DilithiumPublicKey {
    Dilithium2(Box<dilithium2::PublicKey>),
    Dilithium3(Box<dilithium3::PublicKey>),
    Dilithium5(Box<dilithium5::PublicKey>),
}

impl DilithiumPublicKey {
    pub fn level(&self) -> DilithiumLevel {
        match self {
            DilithiumPublicKey::Dilithium2(_) => DilithiumLevel::Dilithium2,
            DilithiumPublicKey::Dilithium3(_) => DilithiumLevel::Dilithium3,
            DilithiumPublicKey::Dilithium5(_) => DilithiumLevel::Dilithium5,
        }
    }

    pub fn size(&self) -> usize {
        self.level().public_key_size()
    }

    pub fn as_bytes(&self) -> &[u8] {
        match self {
            DilithiumPublicKey::Dilithium2(key) => key.as_bytes(),
            DilithiumPublicKey::Dilithium3(key) => key.as_bytes(),
            DilithiumPublicKey::Dilithium5(key) => key.as_bytes(),
        }
    }

    pub fn from_bytes(level: DilithiumLevel, bytes: &[u8]) -> Result<Self> {
        match level {
            DilithiumLevel::Dilithium2 => Ok(DilithiumPublicKey::Dilithium2(Box::new(dilithium2::PublicKey::from_bytes(bytes).map_err(|e| anyhow!(e))?))),
            DilithiumLevel::Dilithium3 => Ok(DilithiumPublicKey::Dilithium3(Box::new(dilithium3::PublicKey::from_bytes(bytes).map_err(|e| anyhow!(e))?))),
            DilithiumLevel::Dilithium5 => Ok(DilithiumPublicKey::Dilithium5(Box::new(dilithium5::PublicKey::from_bytes(bytes).map_err(|e| anyhow!(e))?))),
        }
    }
}

impl std::fmt::Debug for DilithiumPublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DilithiumPublicKey::Dilithium2(_) => f.write_str("Dilithium2PublicKey"),
            DilithiumPublicKey::Dilithium3(_) => f.write_str("Dilithium3PublicKey"),
            DilithiumPublicKey::Dilithium5(_) => f.write_str("Dilithium5PublicKey"),
        }
    }
}

#[derive(Clone)]
pub enum DilithiumSignature {
    Dilithium2(Box<dilithium2::DetachedSignature>),
    Dilithium3(Box<dilithium3::DetachedSignature>),
    Dilithium5(Box<dilithium5::DetachedSignature>),
}

impl DilithiumSignature {
    pub fn level(&self) -> DilithiumLevel {
        match self {
            DilithiumSignature::Dilithium2(_) => DilithiumLevel::Dilithium2,
            DilithiumSignature::Dilithium3(_) => DilithiumLevel::Dilithium3,
            DilithiumSignature::Dilithium5(_) => DilithiumLevel::Dilithium5,
        }
    }

    pub fn size(&self) -> usize {
        self.level().signature_size()
    }

    pub fn as_bytes(&self) -> &[u8] {
        match self {
            DilithiumSignature::Dilithium2(sig) => sig.as_bytes(),
            DilithiumSignature::Dilithium3(sig) => sig.as_bytes(),
            DilithiumSignature::Dilithium5(sig) => sig.as_bytes(),
        }
    }

    pub fn from_bytes(level: DilithiumLevel, bytes: &[u8]) -> Result<Self> {
        match level {
            DilithiumLevel::Dilithium2 => Ok(DilithiumSignature::Dilithium2(Box::new(dilithium2::DetachedSignature::from_bytes(bytes).map_err(|e| anyhow!(e))?))),
            DilithiumLevel::Dilithium3 => Ok(DilithiumSignature::Dilithium3(Box::new(dilithium3::DetachedSignature::from_bytes(bytes).map_err(|e| anyhow!(e))?))),
            DilithiumLevel::Dilithium5 => Ok(DilithiumSignature::Dilithium5(Box::new(dilithium5::DetachedSignature::from_bytes(bytes).map_err(|e| anyhow!(e))?))),
        }
    }
}

impl std::fmt::Debug for DilithiumSignature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DilithiumSignature::Dilithium2(_) => f.write_str("Dilithium2Signature"),
            DilithiumSignature::Dilithium3(_) => f.write_str("Dilithium3Signature"),
            DilithiumSignature::Dilithium5(_) => f.write_str("Dilithium5Signature"),
        }
    }
}

pub fn dilithium_new_keypair(level: DilithiumLevel) -> (DilithiumPublicKey, DilithiumPrivateKey) {
    match level {
        DilithiumLevel::Dilithium2 => {
            let (pk, sk) = dilithium2::keypair();
            (DilithiumPublicKey::Dilithium2(Box::new(pk)), DilithiumPrivateKey::Dilithium2(Box::new(sk)))
        },
        DilithiumLevel::Dilithium3 => {
            let (pk, sk) = dilithium3::keypair();
            (DilithiumPublicKey::Dilithium3(Box::new(pk)), DilithiumPrivateKey::Dilithium3(Box::new(sk)))
        },
        DilithiumLevel::Dilithium5 => {
            let (pk, sk) = dilithium5::keypair();
            (DilithiumPublicKey::Dilithium5(Box::new(pk)), DilithiumPrivateKey::Dilithium5(Box::new(sk)))
        },
    }
}

pub fn dilithium_sign(private_key: &DilithiumPrivateKey, message: impl AsRef<[u8]>) -> DilithiumSignature {
    match private_key {
        DilithiumPrivateKey::Dilithium2(sk) => DilithiumSignature::Dilithium2(Box::new(dilithium2::detached_sign(message.as_ref(), sk))),
        DilithiumPrivateKey::Dilithium3(sk) => DilithiumSignature::Dilithium3(Box::new(dilithium3::detached_sign(message.as_ref(), sk))),
        DilithiumPrivateKey::Dilithium5(sk) => DilithiumSignature::Dilithium5(Box::new(dilithium5::detached_sign(message.as_ref(), sk))),
    }
}

pub fn dilithium_verify(public_key: &DilithiumPublicKey, signature: &DilithiumSignature, message: impl AsRef<[u8]>) -> bool {
    match (public_key, signature) {
        (DilithiumPublicKey::Dilithium2(pk), DilithiumSignature::Dilithium2(sig)) => dilithium2::verify_detached_signature(sig, message.as_ref(), pk).is_ok(),
        (DilithiumPublicKey::Dilithium3(pk), DilithiumSignature::Dilithium3(sig)) => dilithium3::verify_detached_signature(sig, message.as_ref(), pk).is_ok(),
        (DilithiumPublicKey::Dilithium5(pk), DilithiumSignature::Dilithium5(sig)) => dilithium5::verify_detached_signature(sig, message.as_ref(), pk).is_ok(),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use crate::*;

    const MESSAGE: &[u8] = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";

    #[test]
    fn test_dilithium2_signing() {
        let (public_key, private_key) = dilithium_new_keypair(DilithiumLevel::Dilithium2);
        let signature = dilithium_sign(&private_key, MESSAGE);
        assert!(dilithium_verify(&public_key, &signature, MESSAGE));
        assert!(!dilithium_verify(&public_key, &signature, &MESSAGE[..MESSAGE.len() - 1]));
    }

    #[test]
    fn test_dilithium3_signing() {
        let (public_key, private_key) = dilithium_new_keypair(DilithiumLevel::Dilithium3);
        let signature = dilithium_sign(&private_key, MESSAGE);
        assert!(dilithium_verify(&public_key, &signature, MESSAGE));
        assert!(!dilithium_verify(&public_key, &signature, &MESSAGE[..MESSAGE.len() - 1]));
    }

    #[test]
    fn test_dilithium5_signing() {
        let (public_key, private_key) = dilithium_new_keypair(DilithiumLevel::Dilithium5);
        let signature = dilithium_sign(&private_key, MESSAGE);
        assert!(dilithium_verify(&public_key, &signature, MESSAGE));
        assert!(!dilithium_verify(&public_key, &signature, &MESSAGE[..MESSAGE.len() - 1]));
    }
}
