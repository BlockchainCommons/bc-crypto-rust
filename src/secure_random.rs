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

    fn get_rng(&self) -> std::sync::MutexGuard<Option<StdRng>> {
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

pub fn random_data(size: usize) -> Vec<u8> {
    let mut rng_guard = LAZY_RNG.get_rng();
    let rng = rng_guard.as_mut().expect("RNG was not initialized");
    let mut data = vec![0u8; size];
    rng.fill_bytes(&mut data);
    data
}

pub struct SecureRandomNumberGenerator;

impl SecureRandomNumberGenerator {
    pub fn new() -> Self {
        Self
    }
}

impl RandomNumberGenerator for SecureRandomNumberGenerator {
    fn random_data(&mut self, size: usize) -> Vec<u8> {
        random_data(size)
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
