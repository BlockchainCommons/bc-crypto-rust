#[derive(Clone, Debug)]
pub enum CryptoError {
    DecryptFailed
}

impl std::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", &self)
    }
}

impl std::error::Error for CryptoError { }
