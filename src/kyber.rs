use anyhow::{Result, anyhow};
use pqcrypto_kyber::*;
use pqcrypto_traits::kem::{ SecretKey, PublicKey, Ciphertext, SharedSecret };

// Same for every KyberLevel
pub const KYBER_SHARED_SECRET_SIZE: usize = kyber512::shared_secret_bytes();

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KyberLevel {
    Kyber512,
    Kyber768,
    Kyber1024,
}

impl KyberLevel {
    pub fn private_key_size(&self) -> usize {
        match self {
            KyberLevel::Kyber512 => kyber512::secret_key_bytes(),
            KyberLevel::Kyber768 => kyber768::secret_key_bytes(),
            KyberLevel::Kyber1024 => kyber1024::secret_key_bytes(),
        }
    }

    pub fn public_key_size(&self) -> usize {
        match self {
            KyberLevel::Kyber512 => kyber512::public_key_bytes(),
            KyberLevel::Kyber768 => kyber768::public_key_bytes(),
            KyberLevel::Kyber1024 => kyber1024::public_key_bytes(),
        }
    }

    pub fn shared_secret_size(&self) -> usize {
        match self {
            KyberLevel::Kyber512 => kyber512::shared_secret_bytes(),
            KyberLevel::Kyber768 => kyber768::shared_secret_bytes(),
            KyberLevel::Kyber1024 => kyber1024::shared_secret_bytes(),
        }
    }

    pub fn ciphertext_size(&self) -> usize {
        match self {
            KyberLevel::Kyber512 => kyber512::ciphertext_bytes(),
            KyberLevel::Kyber768 => kyber768::ciphertext_bytes(),
            KyberLevel::Kyber1024 => kyber1024::ciphertext_bytes(),
        }
    }
}

#[derive(Clone, PartialEq)]
pub enum KyberPrivateKey {
    Kyber512(Box<kyber512::SecretKey>),
    Kyber768(Box<kyber768::SecretKey>),
    Kyber1024(Box<kyber1024::SecretKey>),
}

impl KyberPrivateKey {
    pub fn level(&self) -> KyberLevel {
        match self {
            KyberPrivateKey::Kyber512(_) => KyberLevel::Kyber512,
            KyberPrivateKey::Kyber768(_) => KyberLevel::Kyber768,
            KyberPrivateKey::Kyber1024(_) => KyberLevel::Kyber1024,
        }
    }

    pub fn size(&self) -> usize {
        self.level().private_key_size()
    }

    pub fn as_bytes(&self) -> &[u8] {
        match self {
            KyberPrivateKey::Kyber512(sk) => sk.as_ref().as_bytes(),
            KyberPrivateKey::Kyber768(sk) => sk.as_ref().as_bytes(),
            KyberPrivateKey::Kyber1024(sk) => sk.as_ref().as_bytes(),
        }
    }

    pub fn from_bytes(level: KyberLevel, bytes: &[u8]) -> Result<Self> {
        match level {
            KyberLevel::Kyber512 => Ok(KyberPrivateKey::Kyber512(Box::new(kyber512::SecretKey::from_bytes(bytes).map_err(|e| anyhow!(e))?))),
            KyberLevel::Kyber768 => Ok(KyberPrivateKey::Kyber768(Box::new(kyber768::SecretKey::from_bytes(bytes).map_err(|e| anyhow!(e))?))),
            KyberLevel::Kyber1024 => Ok(KyberPrivateKey::Kyber1024(Box::new(kyber1024::SecretKey::from_bytes(bytes).map_err(|e| anyhow!(e))?))),
        }
    }
}

impl std::fmt::Debug for KyberPrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KyberPrivateKey::Kyber512(_) => f.write_str("Kyber512PrivateKey"),
            KyberPrivateKey::Kyber768(_) => f.write_str("Kyber768PrivateKey"),
            KyberPrivateKey::Kyber1024(_) => f.write_str("Kyber1024PrivateKey"),
        }
    }
}

#[derive(Clone, PartialEq)]
pub enum KyberPublicKey {
    Kyber512(Box<kyber512::PublicKey>),
    Kyber768(Box<kyber768::PublicKey>),
    Kyber1024(Box<kyber1024::PublicKey>),
}

impl KyberPublicKey {
    pub fn level(&self) -> KyberLevel {
        match self {
            KyberPublicKey::Kyber512(_) => KyberLevel::Kyber512,
            KyberPublicKey::Kyber768(_) => KyberLevel::Kyber768,
            KyberPublicKey::Kyber1024(_) => KyberLevel::Kyber1024,
        }
    }

    pub fn size(&self) -> usize {
        self.level().public_key_size()
    }

    pub fn as_bytes(&self) -> &[u8] {
        match self {
            KyberPublicKey::Kyber512(pk) => pk.as_ref().as_bytes(),
            KyberPublicKey::Kyber768(pk) => pk.as_ref().as_bytes(),
            KyberPublicKey::Kyber1024(pk) => pk.as_ref().as_bytes(),
        }
    }

    pub fn from_bytes(level: KyberLevel, bytes: &[u8]) -> Result<Self> {
        match level {
            KyberLevel::Kyber512 => Ok(KyberPublicKey::Kyber512(Box::new(kyber512::PublicKey::from_bytes(bytes).map_err(|e| anyhow!(e))?))),
            KyberLevel::Kyber768 => Ok(KyberPublicKey::Kyber768(Box::new(kyber768::PublicKey::from_bytes(bytes).map_err(|e| anyhow!(e))?))),
            KyberLevel::Kyber1024 => Ok(KyberPublicKey::Kyber1024(Box::new(kyber1024::PublicKey::from_bytes(bytes).map_err(|e| anyhow!(e))?))),
        }
    }
}

impl std::fmt::Debug for KyberPublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KyberPublicKey::Kyber512(_) => f.write_str("Kyber512PublicKey"),
            KyberPublicKey::Kyber768(_) => f.write_str("Kyber768PublicKey"),
            KyberPublicKey::Kyber1024(_) => f.write_str("Kyber1024PublicKey"),
        }
    }
}

pub fn kyber_new_keypair(level: KyberLevel) -> (KyberPrivateKey, KyberPublicKey) {
    match level {
        KyberLevel::Kyber512 => {
            let (pk, sk) = kyber512::keypair();
            (KyberPrivateKey::Kyber512(sk.into()), KyberPublicKey::Kyber512(pk.into()))
        }
        KyberLevel::Kyber768 => {
            let (pk, sk) = kyber768::keypair();
            (KyberPrivateKey::Kyber768(sk.into()), KyberPublicKey::Kyber768(pk.into()))
        }
        KyberLevel::Kyber1024 => {
            let (pk, sk) = kyber1024::keypair();
            (KyberPrivateKey::Kyber1024(sk.into()), KyberPublicKey::Kyber1024(pk.into()))
        }
    }
}

#[derive(Clone, PartialEq)]
pub enum KyberSharedSecret {
    Kyber512(Box<kyber512::SharedSecret>),
    Kyber768(Box<kyber768::SharedSecret>),
    Kyber1024(Box<kyber1024::SharedSecret>),
}

impl KyberSharedSecret {
    pub fn level(&self) -> KyberLevel {
        match self {
            KyberSharedSecret::Kyber512(_) => KyberLevel::Kyber512,
            KyberSharedSecret::Kyber768(_) => KyberLevel::Kyber768,
            KyberSharedSecret::Kyber1024(_) => KyberLevel::Kyber1024,
        }
    }

    pub fn size(&self) -> usize {
        self.level().shared_secret_size()
    }

    pub fn as_bytes(&self) -> &[u8] {
        match self {
            KyberSharedSecret::Kyber512(ss) => ss.as_ref().as_bytes(),
            KyberSharedSecret::Kyber768(ss) => ss.as_ref().as_bytes(),
            KyberSharedSecret::Kyber1024(ss) => ss.as_ref().as_bytes(),
        }
    }

    pub fn from_bytes(level: KyberLevel, bytes: &[u8]) -> Result<Self> {
        match level {
            KyberLevel::Kyber512 => Ok(KyberSharedSecret::Kyber512(Box::new(kyber512::SharedSecret::from_bytes(bytes).map_err(|e| anyhow!(e))?))),
            KyberLevel::Kyber768 => Ok(KyberSharedSecret::Kyber768(Box::new(kyber768::SharedSecret::from_bytes(bytes).map_err(|e| anyhow!(e))?))),
            KyberLevel::Kyber1024 => Ok(KyberSharedSecret::Kyber1024(Box::new(kyber1024::SharedSecret::from_bytes(bytes).map_err(|e| anyhow!(e))?))),
        }
    }
}

impl std::fmt::Debug for KyberSharedSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KyberSharedSecret::Kyber512(_) => f.write_str("Kyber512SharedSecret"),
            KyberSharedSecret::Kyber768(_) => f.write_str("Kyber768SharedSecret"),
            KyberSharedSecret::Kyber1024(_) => f.write_str("Kyber1024SharedSecret"),
        }
    }
}

#[derive(Clone, PartialEq)]
pub enum KyberCiphertext {
    Kyber512(Box<kyber512::Ciphertext>),
    Kyber768(Box<kyber768::Ciphertext>),
    Kyber1024(Box<kyber1024::Ciphertext>),
}

impl KyberCiphertext {
    pub fn level(&self) -> KyberLevel {
        match self {
            KyberCiphertext::Kyber512(_) => KyberLevel::Kyber512,
            KyberCiphertext::Kyber768(_) => KyberLevel::Kyber768,
            KyberCiphertext::Kyber1024(_) => KyberLevel::Kyber1024,
        }
    }

    pub fn size(&self) -> usize {
        self.level().ciphertext_size()
    }

    pub fn as_bytes(&self) -> &[u8] {
        match self {
            KyberCiphertext::Kyber512(ct) => ct.as_ref().as_bytes(),
            KyberCiphertext::Kyber768(ct) => ct.as_ref().as_bytes(),
            KyberCiphertext::Kyber1024(ct) => ct.as_ref().as_bytes(),
        }
    }

    pub fn from_bytes(level: KyberLevel, bytes: &[u8]) -> Result<Self> {
        match level {
            KyberLevel::Kyber512 => Ok(KyberCiphertext::Kyber512(Box::new(kyber512::Ciphertext::from_bytes(bytes).map_err(|e| anyhow!(e))?))),
            KyberLevel::Kyber768 => Ok(KyberCiphertext::Kyber768(Box::new(kyber768::Ciphertext::from_bytes(bytes).map_err(|e| anyhow!(e))?))),
            KyberLevel::Kyber1024 => Ok(KyberCiphertext::Kyber1024(Box::new(kyber1024::Ciphertext::from_bytes(bytes).map_err(|e| anyhow!(e))?))),
        }
    }
}

impl std::fmt::Debug for KyberCiphertext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KyberCiphertext::Kyber512(_) => f.write_str("Kyber512Ciphertext"),
            KyberCiphertext::Kyber768(_) => f.write_str("Kyber768Ciphertext"),
            KyberCiphertext::Kyber1024(_) => f.write_str("Kyber1024Ciphertext"),
        }
    }
}

pub fn kyber_encapsulate_new_shared_secret(public_key: &KyberPublicKey) -> (KyberSharedSecret, KyberCiphertext) {
    match public_key {
        KyberPublicKey::Kyber512(pk) => {
            let (ss, ct) = kyber512::encapsulate(pk.as_ref());
            (KyberSharedSecret::Kyber512(ss.into()), KyberCiphertext::Kyber512(ct.into()))
        }
        KyberPublicKey::Kyber768(pk) => {
            let (ss, ct) = kyber768::encapsulate(pk.as_ref());
            (KyberSharedSecret::Kyber768(ss.into()), KyberCiphertext::Kyber768(ct.into()))
        }
        KyberPublicKey::Kyber1024(pk) => {
            let (ss, ct) = kyber1024::encapsulate(pk.as_ref());
            (KyberSharedSecret::Kyber1024(ss.into()), KyberCiphertext::Kyber1024(ct.into()))
        }
    }
}

pub fn kyber_decapsulate_shared_secret(ciphertext: &KyberCiphertext, private_key: &KyberPrivateKey) -> KyberSharedSecret {
    match (ciphertext, private_key) {
        (KyberCiphertext::Kyber512(ct), KyberPrivateKey::Kyber512(sk)) => {
            let ss = kyber512::decapsulate(ct.as_ref(), sk.as_ref());
            KyberSharedSecret::Kyber512(ss.into())
        }
        (KyberCiphertext::Kyber768(ct), KyberPrivateKey::Kyber768(sk)) => {
            let ss = kyber768::decapsulate(ct.as_ref(), sk.as_ref());
            KyberSharedSecret::Kyber768(ss.into())
        }
        (KyberCiphertext::Kyber1024(ct), KyberPrivateKey::Kyber1024(sk)) => {
            let ss = kyber1024::decapsulate(ct.as_ref(), sk.as_ref());
            KyberSharedSecret::Kyber1024(ss.into())
        }
        _ => panic!("Kyber level mismatch"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    pub fn test_kyber512() {
        let (private_key, public_key) = kyber_new_keypair(KyberLevel::Kyber512);
        let (shared_secret_1, ciphertext) = kyber_encapsulate_new_shared_secret(&public_key);
        assert_eq!(private_key.size(), 1632);
        assert_eq!(public_key.size(), 800);
        assert_eq!(shared_secret_1.size(), 32);
        assert_eq!(ciphertext.size(), 768);
        let shared_secret_2 = kyber_decapsulate_shared_secret(&ciphertext, &private_key);
        assert_eq!(shared_secret_1, shared_secret_2);
    }

    #[test]
    pub fn test_kyber768() {
        let (private_key, public_key) = kyber_new_keypair(KyberLevel::Kyber768);
        let (shared_secret_1, ciphertext) = kyber_encapsulate_new_shared_secret(&public_key);
        assert_eq!(private_key.size(), 2400);
        assert_eq!(public_key.size(), 1184);
        assert_eq!(shared_secret_1.size(), 32);
        assert_eq!(ciphertext.size(), 1088);
        let shared_secret_2 = kyber_decapsulate_shared_secret(&ciphertext, &private_key);
        assert_eq!(shared_secret_1, shared_secret_2);
    }

    #[test]
    pub fn test_kyber1024() {
        let (private_key, public_key) = kyber_new_keypair(KyberLevel::Kyber1024);
        let (shared_secret_1, ciphertext) = kyber_encapsulate_new_shared_secret(&public_key);
        assert_eq!(private_key.size(), 3168);
        assert_eq!(public_key.size(), 1568);
        assert_eq!(shared_secret_1.size(), 32);
        assert_eq!(ciphertext.size(), 1568);
        let shared_secret_2 = kyber_decapsulate_shared_secret(&ciphertext, &private_key);
        assert_eq!(shared_secret_1, shared_secret_2);
    }
}
