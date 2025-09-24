use argon2::Argon2;

pub fn argon2id(
    pass: impl AsRef<[u8]>,
    salt: impl AsRef<[u8]>,
    output_len: usize,
) -> Vec<u8> {
    let mut output = vec![0u8; output_len];
    Argon2::default()
        .hash_password_into(pass.as_ref(), salt.as_ref(), &mut output)
        .expect("argon2 failed");
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_argon2id_basic() {
        let pass = b"password";
        let salt = b"example salt";
        let output = argon2id(pass, salt, 32);
        assert_eq!(output.len(), 32);
        // Argon2 should be deterministic for same input
        let output2 = argon2id(pass, salt, 32);
        assert_eq!(output, output2);
    }

    #[test]
    fn test_argon2id_different_salt() {
        let pass = b"password";
        let salt1 = b"example salt";
        let salt2 = b"example salt2";
        let out1 = argon2id(pass, salt1, 32);
        let out2 = argon2id(pass, salt2, 32);
        assert_ne!(out1, out2);
    }
}
