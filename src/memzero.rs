/// Zero out a slice of bytes
pub fn memzero<T>(s: &mut [T]) {
    s.iter_mut().for_each(|x| unsafe {
        std::ptr::write_volatile(x, std::mem::zeroed())
    });
}

/// Zero out a vector of vector of bytes
pub fn memzero_vec_vec_u8(s: &mut [Vec<u8>]) {
    s.iter_mut().for_each(|x| memzero(x));
}
