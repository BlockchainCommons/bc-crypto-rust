#[derive(Debug)]
pub enum Error {
    DecryptFailed
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Error::DecryptFailed => "Decrypt failed".to_string(),
        };
        f.write_str(&s)
    }
}

impl std::error::Error for Error { }
