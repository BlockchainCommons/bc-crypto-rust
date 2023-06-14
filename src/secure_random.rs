use std::sync::Once;
use rand::{SeedableRng, rngs::StdRng, RngCore};
use getrandom::getrandom;

use crate::RandomNumberGenerator;

// A wrapper for lazy RNG initialization and thread safety
struct LazyStdRng {
    rng: std::sync::Mutex<Option<StdRng>>,
    init: Once,
}

impl LazyStdRng {
    fn new() -> Self {
        Self {
            rng: std::sync::Mutex::new(None),
            init: Once::new(),
        }
    }

    fn get_rng(&self) -> std::sync::MutexGuard<'_, Option<StdRng>> {
        self.init.call_once(|| {
            let mut seed = [0u8; 32];
            getrandom(&mut seed).expect("Failed to seed RNG");
            let rng = StdRng::from_seed(seed);

            let mut guard = self.rng.lock().expect("Mutex was poisoned");
            *guard = Some(rng);
        });

        self.rng.lock().expect("Mutex was poisoned")
    }
}

lazy_static::lazy_static! {
    static ref LAZY_RNG: LazyStdRng = LazyStdRng::new();
}

/// Generate a vector of cryptographically strong random bytes of the given size.
pub fn random_data(size: usize) -> Vec<u8> {
    let mut rng_guard = LAZY_RNG.get_rng();
    let rng = rng_guard.as_mut().expect("RNG was not initialized");
    let mut data = vec![0u8; size];
    rng.fill_bytes(&mut data);
    data
}

/// Fill the given slice with cryptographically strong random bytes.
pub fn fill_random_data(data: &mut [u8]) {
    let mut rng_guard = LAZY_RNG.get_rng();
    let rng = rng_guard.as_mut().expect("RNG was not initialized");
    rng.fill_bytes(data);
}

pub fn next_u64() -> u64 {
    let mut rng_guard = LAZY_RNG.get_rng();
    let rng = rng_guard.as_mut().expect("RNG was not initialized");
    rng.next_u64()
}

/// A random number generator that can be used as a source of cryptographically-strong
/// randomness.
pub struct SecureRandomNumberGenerator;

impl RandomNumberGenerator for SecureRandomNumberGenerator {
    fn next_u64(&mut self) -> u64 {
        next_u64()
    }

    fn random_data(&mut self, size: usize) -> Vec<u8> {
        random_data(size)
    }

    fn fill_random_data(&mut self, data: &mut [u8]) {
        fill_random_data(data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_random_data() {
        let data1 = random_data(32);
        let data2 = random_data(32);
        let data3 = random_data(32);
        assert_eq!(data1.len(), 32);
        assert_ne!(data1, data2);
        assert_ne!(data1, data3);
    }
}
