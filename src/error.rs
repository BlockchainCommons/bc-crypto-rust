use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("decrypt failed")]
    DecryptFailed
}
