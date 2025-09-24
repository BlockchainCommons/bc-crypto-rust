use scrypt::scrypt as scrypt_hash;

/// Computes the scrypt key derivation function using recommended parameters.
///
/// # Arguments
///
/// * `pass` - The password or passphrase as a byte slice.
/// * `salt` - The salt as a byte slice.
/// * `output_len` - The desired length of the derived key in bytes. Must be
///   greater than 9 and less than or equal to 64.
///
/// # Returns
///
/// A `Vec<u8>` containing the derived key of the specified length.
///
/// # Panics
///
/// Panics if the scrypt function fails or if the output length is invalid.
///
/// # Examples
///
/// ```
/// use bc_crypto::scrypt;
/// let key = scrypt(b"password", b"salt", 32);
/// assert_eq!(key.len(), 32);
/// ```
pub fn scrypt(
    pass: impl AsRef<[u8]>,
    salt: impl AsRef<[u8]>,
    output_len: usize, /* Must be greater than `9` and less than or equal to
                        * `64` */
) -> Vec<u8> {
    let params = scrypt::Params::recommended();
    let mut output = vec![0u8; output_len];
    scrypt_hash(pass.as_ref(), salt.as_ref(), &params, &mut output)
        .expect("scrypt failed");
    output
}

pub fn scrypt_opt(
    pass: impl AsRef<[u8]>,
    salt: impl AsRef<[u8]>,
    output_len: usize, /* Must be greater than `9` and less than or equal to
                        * `64` */
    log_n: u8, // Must be less than `64`
    r: u32,    // Must be greater than 0 and less than or equal to `4294967295`
    p: u32,    // Must be greater than 0 and less than `4294967295`
) -> Vec<u8> {
    let params = scrypt::Params::new(log_n, r, p, output_len)
        .expect("Invalid Scrypt parameters");
    let mut output = vec![0u8; output_len];
    scrypt_hash(pass.as_ref(), salt.as_ref(), &params, &mut output)
        .expect("scrypt failed");
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scrypt_basic() {
        let pass = b"password";
        let salt = b"salt";
        let output = scrypt(pass, salt, 32);
        assert_eq!(output.len(), 32);
        // Scrypt should be deterministic for same input
        let output2 = scrypt(pass, salt, 32);
        assert_eq!(output, output2);
    }

    #[test]
    fn test_scrypt_different_salt() {
        let pass = b"password";
        let salt1 = b"salt1";
        let salt2 = b"salt2";
        let out1 = scrypt(pass, salt1, 32);
        let out2 = scrypt(pass, salt2, 32);
        assert_ne!(out1, out2);
    }

    #[test]
    fn test_scrypt_opt_basic() {
        let pass = b"password";
        let salt = b"salt";
        let output = scrypt_opt(pass, salt, 32, 15, 8, 1);
        assert_eq!(output.len(), 32);
    }

    #[test]
    fn test_scrypt_output_length() {
        let pass = b"password";
        let salt = b"salt";
        for len in [16, 24, 32, 64] {
            let output = scrypt(pass, salt, len);
            assert_eq!(output.len(), len);
        }
    }
}
