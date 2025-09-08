use chacha20poly1305::aead::Error as AeadError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("AEAD error")]
    Aead(AeadError),
}

impl From<AeadError> for Error {
    fn from(error: AeadError) -> Self {
        Error::Aead(error)
    }
}

pub type Result<T> = std::result::Result<T, Error>;
